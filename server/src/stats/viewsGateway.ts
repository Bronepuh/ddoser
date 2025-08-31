import {
  WebSocketGateway,
  WebSocketServer,
  OnGatewayConnection,
  OnGatewayDisconnect,
} from '@nestjs/websockets';
import { Server, Socket } from 'socket.io';
import { Logger } from '@nestjs/common';
import dayjs from 'dayjs';

@WebSocketGateway({
  cors: true,
  transports: ['websocket', 'polling'],
  path: '/ddoser/socket.io',
})
export class ViewsGateway implements OnGatewayConnection, OnGatewayDisconnect {
  @WebSocketServer()
  server: Server;

  private readonly logger = new Logger(ViewsGateway.name);

  private views: { [date: string]: number } = {};
  private uniqueUsers: { [date: string]: Set<string> } = {};

  handleConnection(client: Socket) {
    const ipHeader = client.handshake.headers['x-forwarded-for'];
    const ip = Array.isArray(ipHeader)
      ? ipHeader[0]
      : ipHeader || client.handshake.address;
    const today = dayjs().format('YYYY-MM-DD');

    if (!this.views[today]) {
      this.views[today] = 0;
      this.uniqueUsers[today] = new Set();
    }

    this.views[today] += 1;
    this.uniqueUsers[today].add(ip);

    this.logger.log(`Client connected: ${client.id}, IP: ${ip}`);
    this.logger.debug(
      `Views today: ${this.views[today]}, Unique: ${this.uniqueUsers[today].size}`,
    );

    this.server.emit('stats', {
      views: this.views[today],
      uniqueUsers: this.uniqueUsers[today].size,
    });
  }

  handleDisconnect(client: Socket) {
    const ipHeader = client.handshake.headers['x-forwarded-for'];
    const ip = Array.isArray(ipHeader)
      ? ipHeader[0]
      : ipHeader || client.handshake.address;
    this.logger.warn(`Client disconnected: ${client.id}, IP: ${ip}`);
  }
}
