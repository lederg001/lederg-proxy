import { connect } from 'cloudflare:sockets';
import scanner from './worker.mjs';

export default {
  fetch(request, env, ctx) {
    return scanner.fetch(request, env, ctx);
  },
  scheduled(controller, env, ctx) {
    return scanner.scheduled(controller, env, connect, ctx);
  },
};
