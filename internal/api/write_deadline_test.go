package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestClearWriteDeadline_AllowsSlowStream(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/slow", func(c *gin.Context) {
		clearWriteDeadline(c)
		for i := 0; i < 3; i++ {
			_, _ = c.Writer.Write([]byte("chunk"))
			c.Writer.Flush()
			time.Sleep(60 * time.Millisecond)
		}
	})
	srv := httptest.NewUnstartedServer(r)
	srv.Config.WriteTimeout = 100 * time.Millisecond
	srv.Start()
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/slow")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "chunkchunkchunk", string(body))
}
