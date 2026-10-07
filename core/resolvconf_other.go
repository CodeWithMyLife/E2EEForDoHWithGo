//go:build !android

package fastime

// resolv.conf 代管是 Android root 专属能力，其他平台为空操作。
// resolvKeeper 类型在此提供占位定义，保证跨平台编译。
type resolvKeeper struct{}

func (s *Server) startResolvKeeper()                {}
func (s *Server) stopResolvKeeper()                 {}
func (s *Server) resolvKick()                       {}
func (s *Server) resolvStatus() string              { return "" }
func (s *Server) resolvDNSList() ([]string, string) { return nil, "" }
