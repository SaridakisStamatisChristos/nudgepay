import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  vus: 20,
  duration: '2m',
  thresholds: {
    http_req_duration: ['p(95)<500'],
    http_req_failed: ['rate<0.01'],
  },
};

const BASE_URL = __ENV.NUDGEPAY_BASE_URL || 'http://localhost:8000';

export default function () {
  const health = http.get(`${BASE_URL}/healthz`);
  check(health, {
    'health check succeeded': (res) => res.status === 200,
  });

  const marketing = http.get(`${BASE_URL}/`);
  check(marketing, {
    'landing renders': (res) => res.status === 200,
  });

  sleep(1);
}
