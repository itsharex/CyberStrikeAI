package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ExternalMCPClient 外部MCP客户端接口
type ExternalMCPClient interface {
	// Initialize 初始化连接
	Initialize(ctx context.Context) error
	// ListTools 列出工具
	ListTools(ctx context.Context) ([]Tool, error)
	// CallTool 调用工具
	CallTool(ctx context.Context, name string, args map[string]interface{}) (*ToolResult, error)
	// Close 关闭连接
	Close() error
	// IsConnected 检查是否已连接
	IsConnected() bool
	// GetStatus 获取状态
	GetStatus() string
}

// HTTPMCPClient HTTP模式的MCP客户端
type HTTPMCPClient struct {
	url     string
	timeout time.Duration
	client  *http.Client
	logger  *zap.Logger
	mu      sync.RWMutex
	status  string // "disconnected", "connecting", "connected", "error"
}

// NewHTTPMCPClient 创建HTTP模式的MCP客户端
func NewHTTPMCPClient(url string, timeout time.Duration, logger *zap.Logger) *HTTPMCPClient {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &HTTPMCPClient{
		url:     url,
		timeout: timeout,
		client: &http.Client{
			Timeout: timeout,
		},
		logger: logger,
		status: "disconnected",
	}
}

func (c *HTTPMCPClient) setStatus(status string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.status = status
}

func (c *HTTPMCPClient) GetStatus() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.status
}

func (c *HTTPMCPClient) IsConnected() bool {
	return c.GetStatus() == "connected"
}

func (c *HTTPMCPClient) Initialize(ctx context.Context) error {
	c.setStatus("connecting")

	req := Message{
		ID:      MessageID{value: "1"},
		Method:  "initialize",
		Version: "2.0",
	}

	params := InitializeRequest{
		ProtocolVersion: ProtocolVersion,
		Capabilities:    make(map[string]interface{}),
		ClientInfo: ClientInfo{
			Name:    "CyberStrikeAI",
			Version: "1.0.0",
		},
	}

	paramsJSON, _ := json.Marshal(params)
	req.Params = paramsJSON

	_, err := c.sendRequest(ctx, &req)
	if err != nil {
		c.setStatus("error")
		return fmt.Errorf("初始化失败: %w", err)
	}

	c.setStatus("connected")
	return nil
}

func (c *HTTPMCPClient) ListTools(ctx context.Context) ([]Tool, error) {
	req := Message{
		ID:      MessageID{value: uuid.New().String()},
		Method:  "tools/list",
		Version: "2.0",
	}

	req.Params = json.RawMessage("{}")

	resp, err := c.sendRequest(ctx, &req)
	if err != nil {
		return nil, fmt.Errorf("获取工具列表失败: %w", err)
	}

	var listResp ListToolsResponse
	if err := json.Unmarshal(resp.Result, &listResp); err != nil {
		return nil, fmt.Errorf("解析工具列表失败: %w", err)
	}

	return listResp.Tools, nil
}

func (c *HTTPMCPClient) CallTool(ctx context.Context, name string, args map[string]interface{}) (*ToolResult, error) {
	req := Message{
		ID:      MessageID{value: uuid.New().String()},
		Method:  "tools/call",
		Version: "2.0",
	}

	callReq := CallToolRequest{
		Name:      name,
		Arguments: args,
	}

	paramsJSON, _ := json.Marshal(callReq)
	req.Params = paramsJSON

	resp, err := c.sendRequest(ctx, &req)
	if err != nil {
		return nil, fmt.Errorf("调用工具失败: %w", err)
	}

	var callResp CallToolResponse
	if err := json.Unmarshal(resp.Result, &callResp); err != nil {
		return nil, fmt.Errorf("解析工具调用结果失败: %w", err)
	}

	return &ToolResult{
		Content: callResp.Content,
		IsError: callResp.IsError,
	}, nil
}

func (c *HTTPMCPClient) sendRequest(ctx context.Context, msg *Message) (*Message, error) {
	body, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("序列化请求失败: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("创建HTTP请求失败: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("HTTP请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP错误 %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var mcpResp Message
	if err := json.NewDecoder(resp.Body).Decode(&mcpResp); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}

	if mcpResp.Error != nil {
		return nil, fmt.Errorf("MCP错误: %s (code: %d)", mcpResp.Error.Message, mcpResp.Error.Code)
	}

	return &mcpResp, nil
}

func (c *HTTPMCPClient) Close() error {
	c.setStatus("disconnected")
	return nil
}

// StdioMCPClient stdio模式的MCP客户端
type StdioMCPClient struct {
	command     string
	args        []string
	timeout     time.Duration
	cmd         *exec.Cmd
	stdin       io.WriteCloser
	stdout      io.ReadCloser
	decoder     *json.Decoder
	encoder     *json.Encoder
	logger      *zap.Logger
	mu          sync.RWMutex
	status      string
	requestID   int64
	responses   map[string]chan *Message
	responsesMu sync.Mutex
	ctx         context.Context
	cancel      context.CancelFunc
}

// NewStdioMCPClient 创建stdio模式的MCP客户端
func NewStdioMCPClient(command string, args []string, timeout time.Duration, logger *zap.Logger) *StdioMCPClient {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &StdioMCPClient{
		command:   command,
		args:      args,
		timeout:   timeout,
		logger:    logger,
		status:    "disconnected",
		responses: make(map[string]chan *Message),
		ctx:       ctx,
		cancel:    cancel,
	}
}

func (c *StdioMCPClient) setStatus(status string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.status = status
}

func (c *StdioMCPClient) GetStatus() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.status
}

func (c *StdioMCPClient) IsConnected() bool {
	return c.GetStatus() == "connected"
}

func (c *StdioMCPClient) Initialize(ctx context.Context) error {
	c.setStatus("connecting")

	if err := c.startProcess(); err != nil {
		c.setStatus("error")
		return fmt.Errorf("启动进程失败: %w", err)
	}

	// 启动响应读取goroutine
	go c.readResponses()

	// 发送初始化请求
	req := Message{
		ID:      MessageID{value: "1"},
		Method:  "initialize",
		Version: "2.0",
	}

	params := InitializeRequest{
		ProtocolVersion: ProtocolVersion,
		Capabilities:    make(map[string]interface{}),
		ClientInfo: ClientInfo{
			Name:    "CyberStrikeAI",
			Version: "1.0.0",
		},
	}

	paramsJSON, _ := json.Marshal(params)
	req.Params = paramsJSON

	_, err := c.sendRequest(ctx, &req)
	if err != nil {
		c.setStatus("error")
		c.Close()
		return fmt.Errorf("初始化失败: %w", err)
	}

	c.setStatus("connected")
	return nil
}

func (c *StdioMCPClient) startProcess() error {
	cmd := exec.CommandContext(c.ctx, c.command, c.args...)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		stdin.Close()
		return err
	}

	if err := cmd.Start(); err != nil {
		stdin.Close()
		stdout.Close()
		return err
	}

	c.cmd = cmd
	c.stdin = stdin
	c.stdout = stdout
	c.decoder = json.NewDecoder(stdout)
	c.encoder = json.NewEncoder(stdin)

	return nil
}

func (c *StdioMCPClient) readResponses() {
	defer func() {
		if r := recover(); r != nil {
			c.logger.Error("读取响应时发生panic", zap.Any("error", r))
		}
	}()

	for {
		var msg Message
		if err := c.decoder.Decode(&msg); err != nil {
			if err == io.EOF {
				c.setStatus("disconnected")
				break
			}
			c.logger.Error("读取响应失败", zap.Error(err))
			break
		}

		// 处理响应
		id := msg.ID.String()
		c.responsesMu.Lock()
		if ch, ok := c.responses[id]; ok {
			select {
			case ch <- &msg:
			default:
			}
			delete(c.responses, id)
		}
		c.responsesMu.Unlock()
	}
}

func (c *StdioMCPClient) sendRequest(ctx context.Context, msg *Message) (*Message, error) {
	if c.encoder == nil {
		return nil, fmt.Errorf("进程未启动")
	}

	id := msg.ID.String()
	if id == "" {
		c.mu.Lock()
		c.requestID++
		id = fmt.Sprintf("%d", c.requestID)
		msg.ID = MessageID{value: id}
		c.mu.Unlock()
	}

	// 创建响应通道
	responseCh := make(chan *Message, 1)
	c.responsesMu.Lock()
	c.responses[id] = responseCh
	c.responsesMu.Unlock()

	// 发送请求
	if err := c.encoder.Encode(msg); err != nil {
		c.responsesMu.Lock()
		delete(c.responses, id)
		c.responsesMu.Unlock()
		return nil, fmt.Errorf("发送请求失败: %w", err)
	}

	// 等待响应
	select {
	case resp := <-responseCh:
		if resp.Error != nil {
			return nil, fmt.Errorf("MCP错误: %s (code: %d)", resp.Error.Message, resp.Error.Code)
		}
		return resp, nil
	case <-ctx.Done():
		c.responsesMu.Lock()
		delete(c.responses, id)
		c.responsesMu.Unlock()
		return nil, ctx.Err()
	case <-time.After(c.timeout):
		c.responsesMu.Lock()
		delete(c.responses, id)
		c.responsesMu.Unlock()
		return nil, fmt.Errorf("请求超时")
	}
}

func (c *StdioMCPClient) ListTools(ctx context.Context) ([]Tool, error) {
	req := Message{
		ID:      MessageID{value: uuid.New().String()},
		Method:  "tools/list",
		Version: "2.0",
	}

	req.Params = json.RawMessage("{}")

	resp, err := c.sendRequest(ctx, &req)
	if err != nil {
		return nil, fmt.Errorf("获取工具列表失败: %w", err)
	}

	var listResp ListToolsResponse
	if err := json.Unmarshal(resp.Result, &listResp); err != nil {
		return nil, fmt.Errorf("解析工具列表失败: %w", err)
	}

	return listResp.Tools, nil
}

func (c *StdioMCPClient) CallTool(ctx context.Context, name string, args map[string]interface{}) (*ToolResult, error) {
	req := Message{
		ID:      MessageID{value: uuid.New().String()},
		Method:  "tools/call",
		Version: "2.0",
	}

	callReq := CallToolRequest{
		Name:      name,
		Arguments: args,
	}

	paramsJSON, _ := json.Marshal(callReq)
	req.Params = paramsJSON

	resp, err := c.sendRequest(ctx, &req)
	if err != nil {
		return nil, fmt.Errorf("调用工具失败: %w", err)
	}

	var callResp CallToolResponse
	if err := json.Unmarshal(resp.Result, &callResp); err != nil {
		return nil, fmt.Errorf("解析工具调用结果失败: %w", err)
	}

	return &ToolResult{
		Content: callResp.Content,
		IsError: callResp.IsError,
	}, nil
}

func (c *StdioMCPClient) Close() error {
	c.cancel()

	if c.stdin != nil {
		c.stdin.Close()
	}
	if c.stdout != nil {
		c.stdout.Close()
	}
	if c.cmd != nil {
		c.cmd.Process.Kill()
		c.cmd.Wait()
	}

	c.setStatus("disconnected")
	return nil
}
