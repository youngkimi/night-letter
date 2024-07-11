## Prometheus / Grafana를 활용한 Monitoring System

### Requirements

- 스프링으로 작성된 서버의 Metric 정보를 수집할 것이다.
- Throughtput, Latency를 측정한다.
- Grafana를 통한 데이터 시각화까지 진행한다.
- Nginx를 통해서 Reverse Proxy 되어야 한다. (Url Prefix 필요)
- 컨테이너 환경에서 실행한다.

### Configurations

#### Docker-compose

```yml
services:
  prometheus:
    container_name: prometheus
    image: prom/prometheus
    restart: unless-stopped
    volumes:
      # 컨테이너 외부에서 설정을 변경할 수 있게 bind 한다.
      - type: bind
        source: ./prometheus/prometheus.yml
        target: /etc/prometheus/prometheus.yml
    command:
      # web.enalbe-lifecycle 설정으로 api 재시작없이 설정파일들을 reload 할 수 있게 한다.
      - "--web.enable-lifecycle"
      # prometheus 설정 파일의 위치.
      - "--config.file=/etc/prometheus/prometheus.yml"
      # 외부에서 Prometheus로 접근할 수 있는 URL
      - "--web.external-url=/prometheus/"
      # 내부에서 사용하는 endpoint. web.external-url가 디폴트.
      # 만약 rewrite로 /prometheus/ 블록 제거하면 "/"로 설정해야
      - "--web.route-prefix=/prometheus/"
    ports:
      - 19091:9090
    networks:
      - some-network

  grafana:
    container_name: grafana
    image: grafana/grafana
    restart: unless-stopped
    volumes:
      - ./grafana/datasources:/etc/grafana/provisioning/datasources
    ports:
      - 19092:3000
    networks:
      - some-network

networks:
  some-network:
    external: true
```

#### prometheus.yml

```yml
global:
  scrape_interval: 15s
  scrape_timeout: 10s
  evaluation_interval: 15s
alerting:
  alertmanagers:
    - static_configs:
        - targets: []
      # scheme: http
      # timeout: 10s
      # api_version: v1
scrape_configs:
  - job_name: prometheus
    honor_timestamps: true
    scrape_interval: 15s
    scrape_timeout: 10s
    metrics_path: /system/prometheus
    scheme: http
    static_configs:
      - targets:
          - example.com:9090
```
