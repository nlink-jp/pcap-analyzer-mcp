package mcpserver

import "github.com/nlink-jp/pcap-analyzer-mcp/internal/jsonrpc"

type initializeResult struct {
	ProtocolVersion string         `json:"protocolVersion"`
	Capabilities    map[string]any `json:"capabilities"`
	ServerInfo      serverInfo     `json:"serverInfo"`
}

type serverInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func (s *Server) handleInitialize(req jsonrpc.Request) error {
	return s.writeResult(req.ID, initializeResult{
		ProtocolVersion: ProtocolVersion,
		Capabilities: map[string]any{
			"tools": map[string]any{},
		},
		ServerInfo: serverInfo{Name: s.name, Version: s.version},
	})
}
