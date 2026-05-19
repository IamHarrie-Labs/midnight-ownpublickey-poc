export const CONFIG = {
  proofServerUri: process.env.PROOF_SERVER_URI ?? 'http://localhost:6300',
  indexerUri:     process.env.INDEXER_URI     ?? 'http://localhost:8088/api/v1/graphql',
  indexerWsUri:   process.env.INDEXER_WS_URI  ?? 'ws://localhost:8088/api/v1/graphql/ws',
  nodeUri:        process.env.NODE_URI         ?? 'http://localhost:9933',
};
