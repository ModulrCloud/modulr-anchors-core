package utils

import "github.com/modulrcloud/modulr-anchors-core/cryptography"

func QuorumMap(quorum []string) map[string]bool {
	quorumMap := make(map[string]bool, len(quorum))
	for _, pk := range quorum {
		quorumMap[pk] = true
	}
	return quorumMap
}

func CountVerifiedQuorumSignatures(signatures map[string]string, quorumMap map[string]bool, dataToVerify string) int {
	verified := 0
	seen := make(map[string]struct{}, len(signatures))

	for pubKey, signature := range signatures {
		if signature == "" || !quorumMap[pubKey] {
			continue
		}
		if _, duplicate := seen[pubKey]; duplicate {
			continue
		}
		if !cryptography.VerifySignature(dataToVerify, pubKey, signature) {
			continue
		}

		seen[pubKey] = struct{}{}
		verified++
	}

	return verified
}

func HasVerifiedQuorumSignatures(signatures map[string]string, quorumMap map[string]bool, dataToVerify string, majority int) bool {
	return CountVerifiedQuorumSignatures(signatures, quorumMap, dataToVerify) >= majority
}
