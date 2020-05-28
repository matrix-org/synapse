# Using the Synapse Grafana dashboard

0. Set up Prometheus and Grafana. Out of scope for this readme. Useful documentation about using Grafana with Prometheus: http://docs.grafana.org/features/datasources/prometheus/
1. Have your Prometheus scrape your Synapse. https://github.com/matrix-org/synapse/blob/master/docs/metrics-howto.md
2. Import dashboard into Grafana. Download `synapse.json`. Import it to Grafana and select the correct Prometheus datasource. http://docs.grafana.org/reference/export_import/
3. Set up additional recording rules
