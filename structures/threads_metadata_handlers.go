package structures

import "strconv"

type ApprovementThreadMetadataHandler struct {
	NetworkParameters NetworkParameters  `json:"networkParameters"`
	EpochDataHandler  EpochDataHandler   `json:"epoch"`
	SupportedEpochs   []EpochDataHandler `json:"supportedEpochs,omitempty"`
}

func (handler *ApprovementThreadMetadataHandler) GetNetworkParams() NetworkParameters {
	return handler.NetworkParameters
}

func (handler *ApprovementThreadMetadataHandler) GetEpochHandler() EpochDataHandler {
	if len(handler.SupportedEpochs) == 0 {
		return handler.EpochDataHandler
	}
	return handler.SupportedEpochs[len(handler.SupportedEpochs)-1]
}

func (handler *ApprovementThreadMetadataHandler) GetEpochHandlers() []EpochDataHandler {
	if len(handler.SupportedEpochs) == 0 {
		return []EpochDataHandler{handler.EpochDataHandler}
	}
	result := make([]EpochDataHandler, len(handler.SupportedEpochs))
	copy(result, handler.SupportedEpochs)
	return result
}

func (handler *ApprovementThreadMetadataHandler) FindEpochHandlerByFullID(fullID string) (EpochDataHandler, bool) {
	for _, epoch := range handler.GetEpochHandlers() {
		candidateID := epoch.Hash + "#" + strconv.Itoa(epoch.Id)
		if candidateID == fullID {
			return epoch, true
		}
	}
	return EpochDataHandler{}, false
}

func (handler *ApprovementThreadMetadataHandler) SyncEpochPointers() {
	if len(handler.SupportedEpochs) == 0 {
		return
	}
	handler.EpochDataHandler = handler.SupportedEpochs[len(handler.SupportedEpochs)-1]
}

type GenerationThreadMetadataHandler struct {
	EpochFullId string `json:"epochFullId"`
	PrevHash    string `json:"prevHash"`
	NextIndex   int    `json:"nextIndex"`
}
