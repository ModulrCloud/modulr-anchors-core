package structures

type SequenceAlignmentAnchorData struct {
	AggregatedAnchorRotationProof AggregatedAnchorRotationProof `json:"aarp"`
	FoundInBlock                  int                           `json:"foundInBlock"`
}

type SequenceAlignmentDataResponse struct {
	FoundInAnchorIndex int                                 `json:"foundInAnchorIndex"`
	Anchors            map[int]SequenceAlignmentAnchorData `json:"anchors"`
	Afp                *AggregatedFinalizationProof        `json:"afp,omitempty"`
}
