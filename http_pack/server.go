package http_pack

import (
	"fmt"
	"strconv"

	"github.com/modulrcloud/modulr-anchors-core/globals"
	"github.com/modulrcloud/modulr-anchors-core/utils"

	"github.com/fasthttp/router"
	"github.com/valyala/fasthttp"
)

func createRouter() fasthttp.RequestHandler {

	r := router.New()

	r.GET("/block/{id}", GetBlockById)

	r.GET("/aggregated_finalization_proof/{blockId}", GetAggregatedFinalizationProof)

	r.POST("/anchor_rotation_proof", AnchorRotationProof)

	r.POST("/accept_extra_data", AcceptExtraData)
	r.POST("/accept_leader_finalization_data", AcceptLeaderFinalizationData)

	return r.Handler
}

func CreateHTTPServer() {

	serverAddr := globals.CONFIGURATION.Interface + ":" + strconv.Itoa(globals.CONFIGURATION.Port)

	utils.LogWithTime(fmt.Sprintf("Server is starting at http://%s ...✅", serverAddr), utils.CYAN_COLOR)

	if err := fasthttp.ListenAndServe(serverAddr, createRouter()); err != nil {
		utils.LogWithTime(fmt.Sprintf("Error in server: %s", err), utils.RED_COLOR)
	}
}
