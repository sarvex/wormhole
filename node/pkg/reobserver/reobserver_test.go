package reobserver

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	gossipv1 "github.com/certusone/wormhole/node/pkg/proto/gossip/v1"
	"github.com/certusone/wormhole/node/pkg/vaa"

	"github.com/ethereum/go-ethereum/common"
	"go.uber.org/zap"
)

func TestMsgBeforeQuorum(t *testing.T) {
	logger := zap.NewNop()
	obsvReqSendC := make(chan *gossipv1.ObservationRequest, 50)
	reob := NewReobserver(logger, obsvReqSendC)
	assert.NotNil(t, reob)

	msgId := "1/c69a1b1a65dd336bf1df6a77afb501fc25db7fc0938cb08595a9ef473265cb4f/1"

	now := time.Now()
	reob.AddMessage(msgId, vaa.ChainIDSolana, common.Hash{})
	reob.QuorumReached(msgId)

	// Make sure it was received and has been marked completed.
	assert.Equal(t, 1, len(reob.observations))
	oe, exists := reob.observations[msgId]
	assert.Equal(t, true, exists)
	assert.Equal(t, true, oe.localMsgReceived())
	assert.Equal(t, true, oe.quorumReached)
	assert.Equal(t, true, oe.completed)
	assert.Equal(t, 0, oe.numRetries)

	// Make sure it gets expired.
	reob.checkForReobservationsForTime(now.Add(time.Minute * time.Duration(expirationIntervalInMinutes+1)))
	assert.Equal(t, 0, len(reob.observations))
}

func TestQuorumBeforeMsg(t *testing.T) {
	logger := zap.NewNop()
	obsvReqSendC := make(chan *gossipv1.ObservationRequest, 50)
	reob := NewReobserver(logger, obsvReqSendC)
	assert.NotNil(t, reob)

	msgId := "1/c69a1b1a65dd336bf1df6a77afb501fc25db7fc0938cb08595a9ef473265cb4f/1"

	now := time.Now()
	reob.QuorumReached(msgId)
	reob.AddMessage(msgId, vaa.ChainIDSolana, common.Hash{})

	// Make sure it was received and has been marked completed.
	assert.Equal(t, 1, len(reob.observations))
	oe, exists := reob.observations[msgId]
	assert.Equal(t, true, exists)
	assert.Equal(t, true, oe.localMsgReceived())
	assert.Equal(t, true, oe.quorumReached)
	assert.Equal(t, true, oe.completed)
	assert.Equal(t, 0, oe.numRetries)

	// Make sure it gets expired.
	reob.checkForReobservationsForTime(now.Add(time.Minute * time.Duration(expirationIntervalInMinutes+1)))
	assert.Equal(t, 0, len(reob.observations))
}

func TestSuccessAfterRetry(t *testing.T) {
	logger := zap.NewNop()
	obsvReqSendC := make(chan *gossipv1.ObservationRequest, 50)
	reob := NewReobserver(logger, obsvReqSendC)
	assert.NotNil(t, reob)

	msgId := "1/c69a1b1a65dd336bf1df6a77afb501fc25db7fc0938cb08595a9ef473265cb4f/1"

	now := time.Now()
	reob.AddMessage(msgId, vaa.ChainIDSolana, common.Hash{})

	// Make sure it was received.
	assert.Equal(t, 1, len(reob.observations))
	oe, exists := reob.observations[msgId]

	reob.checkForReobservationsForTime(now.Add(time.Minute * time.Duration(expirationIntervalInMinutes+1)))
	assert.Equal(t, 1, len(obsvReqSendC))
	msg := <-obsvReqSendC
	assert.NotNil(t, msg)
	assert.Equal(t, 1, oe.numRetries)

	reob.QuorumReached(msgId)

	// Make sure it was marked completed.
	assert.Equal(t, true, exists)
	assert.Equal(t, true, oe.localMsgReceived())
	assert.Equal(t, true, oe.quorumReached)
	assert.Equal(t, true, oe.completed)
	assert.Equal(t, 1, oe.numRetries)

	// Make sure it gets expired.
	reob.checkForReobservationsForTime(now.Add(time.Minute * time.Duration(expirationIntervalInMinutes+1)))
	assert.Equal(t, 0, len(reob.observations))
}

func TestRetriesFail(t *testing.T) {
	logger := zap.NewNop()
	obsvReqSendC := make(chan *gossipv1.ObservationRequest, 50)
	reob := NewReobserver(logger, obsvReqSendC)
	assert.NotNil(t, reob)

	msgId := "1/c69a1b1a65dd336bf1df6a77afb501fc25db7fc0938cb08595a9ef473265cb4f/1"

	now := time.Now()
	reob.AddMessage(msgId, vaa.ChainIDSolana, common.Hash{})

	// Make sure it was received.
	assert.Equal(t, 1, len(reob.observations))
	oe, exists := reob.observations[msgId]
	assert.Equal(t, true, exists)
	assert.Equal(t, true, oe.localMsgReceived())

	for count := 1; count <= maxRetries; count++ {
		reob.checkForReobservationsForTime(now.Add(time.Minute * time.Duration(count*expirationIntervalInMinutes+1)))
		msg := <-obsvReqSendC
		assert.NotNil(t, msg)
		assert.Equal(t, count, oe.numRetries)
	}

	// Make sure it was not marked completed and got expired.

	assert.Equal(t, false, oe.quorumReached)
	assert.Equal(t, false, oe.completed)
	assert.Equal(t, maxRetries, oe.numRetries)

	// Make sure it gets expired.
	reob.checkForReobservationsForTime(now.Add(time.Minute * time.Duration(expirationIntervalInMinutes+1)))
	assert.Equal(t, 0, len(reob.observations))
}

func TestLimitedRetriesPerInterval(t *testing.T) {
	logger := zap.NewNop()
	obsvReqSendC := make(chan *gossipv1.ObservationRequest, 50)
	reob := NewReobserver(logger, obsvReqSendC)
	assert.NotNil(t, reob)

	now := time.Now()

	// Add more messages than should get published in a single interval.
	for count := 1; count <= maxRetriesPerInterval+1; count++ {
		msgId := fmt.Sprintf("1/c69a1b1a65dd336bf1df6a77afb501fc25db7fc0938cb08595a9ef473265cb4f/%v", count)
		reob.AddMessage(msgId, vaa.ChainIDSolana, common.Hash{})
	}

	// Make sure all the messages were received.
	assert.Equal(t, maxRetriesPerInterval+1, len(reob.observations))

	// Make sure we don't publish anything right away.
	reob.checkForReobservationsForTime(now)
	assert.Equal(t, 0, len(obsvReqSendC))

	// Make sure we limit how many we publish in an interval.
	reob.checkForReobservationsForTime(now.Add(time.Minute * time.Duration(retryIntervalInMinutes+1)))
	assert.Equal(t, maxRetriesPerInterval, len(obsvReqSendC))

	// The next interval, we should publish the remaining one.
	reob.checkForReobservationsForTime(now.Add(time.Minute))
	assert.Equal(t, maxRetriesPerInterval+1, len(obsvReqSendC))
}

func TestExtraNotificationsDoNoHarm(t *testing.T) {
	logger := zap.NewNop()
	obsvReqSendC := make(chan *gossipv1.ObservationRequest, 50)
	reob := NewReobserver(logger, obsvReqSendC)
	assert.NotNil(t, reob)

	msgId := "1/c69a1b1a65dd336bf1df6a77afb501fc25db7fc0938cb08595a9ef473265cb4f/1"

	now := time.Now()
	reob.AddMessage(msgId, vaa.ChainIDSolana, common.Hash{})
	reob.AddMessage(msgId, vaa.ChainIDSolana, common.Hash{})
	reob.QuorumReached(msgId)
	reob.QuorumReached(msgId)
	reob.AddMessage(msgId, vaa.ChainIDSolana, common.Hash{})
	reob.QuorumReached(msgId)

	// Make sure it was received and has been marked completed.
	assert.Equal(t, 1, len(reob.observations))
	oe, exists := reob.observations[msgId]
	assert.Equal(t, true, exists)
	assert.Equal(t, true, oe.localMsgReceived())
	assert.Equal(t, true, oe.quorumReached)
	assert.Equal(t, true, oe.completed)
	assert.Equal(t, 0, oe.numRetries)

	// Make sure it gets expired.
	reob.checkForReobservationsForTime(now.Add(time.Minute * time.Duration(expirationIntervalInMinutes+1)))
	assert.Equal(t, 0, len(reob.observations))
}