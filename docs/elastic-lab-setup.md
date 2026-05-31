# Elastic Lab Setup

Spotter-Shooter uses a **bring-your-own Elastic** model.

The public repository does not connect to the maintainer's private Elastic/Kibana lab. Operators should either:

1. point Spotter-Shooter at an existing Elastic instance they control, or
2. create a fresh Elastic/Kibana lab and import datasets locally.

This is intentional. Threat-hunting datasets can be large, and security teams should control where telemetry lives.

## Recommended options

### Option A — Use your own Elastic

If you already have Elastic/Kibana, use the deployment wizard and provide:

- Elasticsearch URL
- port
- username/password or API key, if required
- index pattern, for example:

```text
botsv3-*,apt29-*,apt3-*,lsass-*,goldensaml-*,log4shell-*
```

### Option B — Build a local lab

Create a single-node Elastic/Kibana stack and bind it to localhost.

Example compose fragment:

```yaml
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.15.3
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - xpack.security.enrollment.enabled=false
      - ES_JAVA_OPTS=-Xms2g -Xmx2g
    ports:
      - "127.0.0.1:9209:9200"
    volumes:
      - esdata:/usr/share/elasticsearch/data

  kibana:
    image: docker.elastic.co/kibana/kibana:8.15.3
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
    ports:
      - "127.0.0.1:5601:5601"

volumes:
  esdata:
```

Then point Spotter-Shooter at:

```text
Elastic URL: http://127.0.0.1
Port: 9209
```

When Spotter-Shooter itself runs in Docker, localhost from the browser is translated internally to the Elastic container only if the operator has attached the containers to the same lab network. Otherwise use a reachable hostname/IP for your Elastic instance.

## Dataset import guidance

The project does not automatically download/import BOTSv3 or APT datasets during `./deploy.sh`.

Reason:

- BOTSv3 alone is large.
- Imports can take a long time.
- Elastic field mappings may need tuning.
- Some users cannot download public datasets from production or air-gapped environments.

Recommended public datasets for evaluation:

- Splunk BOTSv3
- OTRF Security-Datasets APT29 evaluation telemetry
- OTRF APT3 / CALDERA / Empire telemetry
- OTRF LSASS credential-access telemetry
- Log4Shell telemetry
- Golden SAML / ADFS telemetry

After importing, create Kibana data views and point Spotter-Shooter to the matching index patterns.

## Why not ship the data directly?

Shipping a fresh Elastic stack with automatic imports would make the demo easier for one-click use, but worse for most serious teams:

- very large repo/deployment footprint
- long setup time
- possible licensing/distribution questions for datasets
- unpredictable memory/disk requirements
- risk of people accidentally using a shared/private lab

The better default is reproducible BYO Elastic, with optional import scripts or documented dataset walkthroughs.
