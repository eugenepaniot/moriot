{
  debug: false,
  flushInterval: 60000,
  dumpMessages: false,
  flush_counts: false,
  prefixStats: "statsd",
  graphite: {
    legacyNamespace: false,
    globalPrefix: "custom.1m.sysops.sipcapture." + require('os').hostname().split('.')[0] + ".statsd"
  },
  graphitePort: 2013
, graphiteHost: "graphite.int.ringcentral.com"
, address: "127.0.0.1"
, port: 8125
, mgmt_address: "0.0.0.0"
, mgmt_port: 8126
, backends: [ "./backends/graphite" ]
}
