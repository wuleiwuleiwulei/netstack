/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


import type { AsyncCallback, ErrorCallback, Callback } from '@ohos.base';
import type connection from '@ohos.net.connection';
import { BusinessError }  from '@ohos.base';

export default namespace webSocket {
  type HttpProxy = connection.HttpProxy;

  loadLibrary("websocket_ani");

  class Cleaner {
    private nativePtr: long = 0
    constructor(nativePtr:long) {
        this.nativePtr = nativePtr
    }
    native clean(): void
  }

  export native function createWebSocket(): WebSocket;

  let destroyRegister = new FinalizationRegistry<Cleaner>((cleaner: Cleaner) => {cleaner.clean()})
  let unregisterToken = new object()

  export interface WebSocketRequestOptions {
    header?: Record<String, String>;

    caPath?: string;

    clientCert?: ClientCert;

    proxy?: ProxyConfiguration;

    protocol?: string;
  }

  export class WebSocketRequestOptionsInner implements WebSocketRequestOptions {
    header?: Record<String, String>;

    caPath?: string;

    clientCert?: ClientCert;

    proxy?: ProxyConfiguration;

    protocol?: string;
  }

  export type ProxyConfiguration = 'system' | 'no-proxy' | HttpProxy;

  export interface ClientCert {
    certPath: string;

    keyPath: string;

    keyPassword?: string;
  }

  export class ClientCertInner implements ClientCert {
    certPath: string;

    keyPath: string;

    keyPassword?: string;
  }

  export interface WebSocketCloseOptions {
    code?: int;
    reason?: string;
  }

  export class WebSocketCloseOptionsInner implements WebSocketCloseOptions {
    code?: int;
    reason?: string;
  }

  export interface CloseResult {
    code: int;
    reason: string;
  }

  export class CloseResultInner implements CloseResult {
    code: int;
    reason: string;
  }

  export interface OpenResult {
    status: int;
    message: string;
  }

  export class OpenResultInner implements OpenResult {
    status: int;
    message: string;
  }

  export type ResponseHeaders = Record<string, string | string[] | undefined>;

  export interface WebSocket {
    connect(url: string, callback: AsyncCallback<boolean>): void;

    connect(url: string, options: WebSocketRequestOptions, callback: AsyncCallback<boolean>): void;

    connect(url: string, options?: WebSocketRequestOptions): Promise<boolean>;

    send(data: string | ArrayBuffer, callback: AsyncCallback<boolean>): void;

    send(data: string | ArrayBuffer): Promise<boolean>;

    close(callback: AsyncCallback<boolean>): void;

    close(options: WebSocketCloseOptions, callback: AsyncCallback<boolean>): void;

    close(options?: WebSocketCloseOptions): Promise<boolean>;

    onOpen(callback: Callback<OpenResult>): void;

    onMessage(callback: AsyncCallback<string | ArrayBuffer>): void;

    onWebSocketClose(callback: AsyncCallback<CloseResult>): void;

    onWebSocketError(callback: ErrorCallback): void;

    onDataEnd(callback: Callback<void>): void;

    onHeaderReceive(callback: Callback<ResponseHeaders>): void;

    offOpen(callback?: Callback<OpenResult>): void;

    offMessage(callback?: AsyncCallback<string | ArrayBuffer>): void;

    offWebSocketClose(callback?: AsyncCallback<CloseResult>): void;

    offWebSocketError(callback?: ErrorCallback): void;

    offDataEnd(callback?: Callback<void>): void;

    offHeaderReceive(callback?: Callback<ResponseHeaders>): void;
  }

  export class WebSocketInner implements WebSocket {
    private  nativePtr:long = 0;
    private cleaner: Cleaner | null = null;

    constructor(context:long) {
        if(this.nativePtr == 0){
             this.nativePtr = context;
        }
        this.registerCleaner(this.nativePtr)
    }

    registerCleaner(nativePtr: long): void {
      this.cleaner = new Cleaner(nativePtr)
      destroyRegister.register(this, this.cleaner!, unregisterToken);
    }
    unregisterCleaner(): void {
        destroyRegister.unregister(unregisterToken);
    }

    native connectSync(url: string, options?: WebSocketRequestOptions): boolean;

    connect(url: string, callback: AsyncCallback<boolean>): void {
      let p1 = taskpool.execute((): boolean => {
        return this.connectSync(url);
      })
      p1.then((content: Any) => {
          callback(new BusinessError(), content as boolean);
      }, (err: Error): void => {
          callback(err as BusinessError, false);
      });
    }

    connect(url: string, options: WebSocketRequestOptions, callback: AsyncCallback<boolean>): void {
      let p1 = taskpool.execute((): boolean => {
        return this.connectSync(url, options);
      })
      p1.then((content: Any) => {
          callback(new BusinessError(), content as boolean);
      }, (err: Error): void => {
          callback(err as BusinessError, false);
      });
    }

    connect(url: string, options?: WebSocketRequestOptions): Promise<boolean> {
      return new Promise<boolean>((resolve, reject) => {
      taskpool.execute((): boolean => {
          return this.connectSync(url, options);
        }).then((content: Any) => {
            resolve(content as boolean);
        }, (err: Error): void => {
            reject(err as BusinessError);
        });
      });
    }

    native sendSync(data: string | ArrayBuffer): boolean;

    send(data: string | ArrayBuffer, callback: AsyncCallback<boolean>): void {
      let p1 = taskpool.execute((): boolean => {
        return this.sendSync(data);
      })
      p1.then((content: Any) => {
          callback(new BusinessError(), content as boolean);
      }, (err: Error): void => {
          callback(err as BusinessError, false);
      });
    }

    send(data: string | ArrayBuffer): Promise<boolean> {
      return new Promise<boolean>((resolve, reject) => {
      taskpool.execute((): boolean => {
          return this.sendSync(data);
        }).then((content: Any) => {
            resolve(content as boolean);
        }, (err: Error): void => {
            reject(err as BusinessError);
        });
      });
    }

    native closeSync(options?: WebSocketCloseOptions): boolean;

    close(callback: AsyncCallback<boolean>): void {
      let p1 = taskpool.execute((): boolean => {
        return this.closeSync();
      })
      p1.then((content: Any) => {
          callback(new BusinessError(), content as boolean);
      }, (err: Error): void => {
          callback(err as BusinessError, false);
      });
    }

    close(options: WebSocketCloseOptions, callback: AsyncCallback<boolean>): void {
      let p1 = taskpool.execute((): boolean => {
        return this.closeSync(options);
      })
      p1.then((content: Any) => {
          callback(new BusinessError(), content as boolean);
      }, (err: Error): void => {
          callback(err as BusinessError, false);
      });
    }

    close(options?: WebSocketCloseOptions): Promise<boolean> {
      return new Promise<boolean>((resolve, reject) => {
      taskpool.execute((): boolean => {
          return this.closeSync(options);
        }).then((content: Any) => {
            resolve(content as boolean);
        }, (err: Error): void => {
            reject(err as BusinessError);
        });
      });
    }

    native onOpenInner(callback: Callback<OpenResult>): void;
    native onMessageInner(callback: AsyncCallback<string | ArrayBuffer>): void;
    native onCloseInner(callback: AsyncCallback<CloseResult>): void;
    native onErrorInner(callback: ErrorCallback): void;
    native onDataEndInner(callback: Callback<void>): void;
    native onHeaderReceiveInner(callback: Callback<ResponseHeaders>): void;

    onOpen(callback: Callback<OpenResult>): void {
      this.onOpenInner(callback)
    }

    onMessage(callback: AsyncCallback<string | ArrayBuffer>): void {
      this.onMessageInner(callback)
    }

    onWebSocketClose(callback: AsyncCallback<CloseResult>): void {
      this.onCloseInner(callback)
    }

    onWebSocketError(callback: ErrorCallback): void {
      this.onErrorInner(callback)
    }

    onDataEnd(callback: Callback<void>): void {
      this.onDataEndInner(callback)
    }

    onHeaderReceive(callback: Callback<ResponseHeaders>): void {
      this.onHeaderReceiveInner(callback)
    }

    native offOpenInner(callback?: Callback<OpenResult>): void;
    native offMessageInner(callback?: AsyncCallback<string | ArrayBuffer>): void;
    native offCloseInner(callback?: AsyncCallback<CloseResult>): void;
    native offErrorInner(callback?: ErrorCallback): void;
    native offDataEndInner(callback?: Callback<void>): void;
    native offHeaderReceiveInner(callback?: Callback<ResponseHeaders>): void;

    offOpen(callback?: Callback<OpenResult>): void {
      if (callback === undefined) {
        this.offOpenInner()
      } else {
        this.offOpenInner(callback)
      }
    }

    offMessage(callback?: AsyncCallback<string | ArrayBuffer>): void {
      if (callback === undefined) {
        this.offMessageInner()
      } else {
        this.offMessageInner(callback)
      }
    }

    offWebSocketClose(callback?: AsyncCallback<CloseResult>): void {
      if (callback === undefined) {
        this.offCloseInner()
      } else {
        this.offCloseInner(callback)
      }
    }

    offWebSocketError(callback?: ErrorCallback): void {
      if (callback === undefined) {
        this.offErrorInner()
      } else {
        this.offErrorInner(callback)
      }
    }

    offDataEnd(callback?: Callback<void>): void {
      if (callback === undefined) {
        this.offDataEndInner()
      } else {
        this.offDataEndInner(callback)
      }
    }

    offHeaderReceive(callback?: Callback<ResponseHeaders>): void {
      if (callback === undefined) {
        this.offHeaderReceiveInner()
      } else {
        this.offHeaderReceiveInner(callback)
      }
    }
  }

  class CleanerServer {
    private nativePtr: long = 0
    constructor(nativePtr:long) {
        this.nativePtr = nativePtr
    }
    native clean(): void
  }

  let destroyRegisterServer = new FinalizationRegistry<CleanerServer>((cleaner: CleanerServer) => {cleaner.clean()})
  let unregisterTokenServer = new object()

  export native function createWebSocketServer(): WebSocketServer;

  export interface WebSocketServerConfig {
    serverIP?: string;

    serverPort: int;

    serverCert?: ServerCert;

    maxConcurrentClientsNumber: int;

    protocol?: string;

    maxConnectionsForOneClient: int;
  }

  export class WebSocketServerConfigInner implements WebSocketServerConfig {
    serverIP?: string;

    serverPort: int;

    serverCert?: ServerCert;

    maxConcurrentClientsNumber: int;

    protocol?: string;

    maxConnectionsForOneClient: int;
  }

  export interface ServerCert {
    certPath: string;

    keyPath: string;
  }

  export class ServerCertInner implements ServerCert {
    certPath: string;

    keyPath: string;
  }

  export interface WebSocketConnection {
    clientIP: string;

    clientPort: int;
  }

  export class WebSocketConnectionInner implements WebSocketConnection {
    clientIP: string;

    clientPort: int;
  }

  export type ClientConnectionCloseCallback = (clientConnection: WebSocketConnection, closeReason: CloseResult) => void;

  export interface WebSocketMessage {
    data: string | ArrayBuffer;

    clientConnection: WebSocketConnection;
  }

  export class WebSocketMessageInner implements WebSocketMessage {
    data: string | ArrayBuffer;

    clientConnection: WebSocketConnection;
  }

  export interface WebSocketServer {
    start(config: WebSocketServerConfig): Promise<boolean>;

    listAllConnections(): WebSocketConnection[];

    close(connection: WebSocketConnection, options?: WebSocketCloseOptions): Promise<boolean>;

    send(data: string | ArrayBuffer, connection: WebSocketConnection): Promise<boolean>;

    stop(): Promise<boolean>;

    onConnect(callback: Callback<WebSocketConnection>): void;

    onMessageReceive(callback: Callback<WebSocketMessage>): void;

    onWebSocketServerClose(callback: ClientConnectionCloseCallback): void;

    onWebSocketServerError(callback: ErrorCallback): void;

    offConnect(callback?: Callback<WebSocketConnection>): void;

    offMessageReceive(callback?: Callback<WebSocketMessage>): void;

    offWebSocketServerClose(callback?: ClientConnectionCloseCallback): void;

    offWebSocketServerError(callback?: ErrorCallback): void;
  }

  export class WebSocketServerInner implements WebSocketServer {
    private nativePtr: long = 0;
    private cleaner: CleanerServer | null = null;

    constructor(context: long) {
      if (this.nativePtr == 0) {
        this.nativePtr = context;
      }
      this.registerCleaner(this.nativePtr);
    }

    registerCleaner(nativePtr: long): void {
      this.cleaner = new CleanerServer(nativePtr);
      destroyRegisterServer.register(this, this.cleaner!, unregisterTokenServer);
    }

    unregisterCleaner(): void {
      destroyRegisterServer.unregister(unregisterTokenServer);
    }

    native startSync(config: WebSocketServerConfig): boolean;

    start(config: WebSocketServerConfig): Promise<boolean> {
      return new Promise<boolean>((resolve, reject) => {
      taskpool.execute((): boolean => {
          return this.startSync(config);
        }).then((content: Any) => {
            resolve(content as boolean);
        }, (err: Error): void => {
            reject(err as BusinessError);
        });
      });
    }

    native closeSync(connection: WebSocketConnection, options?: webSocket.WebSocketCloseOptions): boolean;

    close(connection: WebSocketConnection, options?: webSocket.WebSocketCloseOptions): Promise<boolean> {
      return new Promise<boolean>((resolve, reject) => {
      taskpool.execute((): boolean => {
          return this.closeSync(connection, options);
        }).then((content: Any) => {
            resolve(content as boolean);
        }, (err: Error): void => {
            reject(err as BusinessError);
        });
      });
    }

    native listAllConnectionsSync(): WebSocketConnection[];

    listAllConnections(): WebSocketConnection[] {
      return this.listAllConnectionsSync();
    }

    native sendSync(data: string | ArrayBuffer, connection: WebSocketConnection): boolean;

    send(data: string | ArrayBuffer, connection: WebSocketConnection): Promise<boolean> {
      return new Promise<boolean>((resolve, reject) => {
      taskpool.execute((): boolean => {
          return this.sendSync(data, connection);
        }).then((content: Any) => {
            resolve(content as boolean);
        }, (err: Error): void => {
            reject(err as BusinessError);
        });
      });
    }

    native stopSync(): boolean;

    stop(): Promise<boolean> {
      return new Promise<boolean>((resolve, reject) => {
      taskpool.execute((): boolean => {
          return this.stopSync();
        }).then((content: Any) => {
            resolve(content as boolean);
        }, (err: Error): void => {
            reject(err as BusinessError);
        });
      });
    }

    native onWebSocketServerErrorInner(callback: ErrorCallback): void;
    native onConnectInner(callback: Callback<WebSocketConnection>): void;
    native onWebSocketServerCloseInner(callback: ClientConnectionCloseCallback): void;
    native onMessageReceiveInner(callback: Callback<WebSocketMessage>): void;

    onWebSocketServerError(callback: ErrorCallback): void {
      this.onWebSocketServerErrorInner(callback);
    }

    onConnect(callback: Callback<WebSocketConnection>): void {
      this.onConnectInner(callback);
    }

    onWebSocketServerClose(callback: ClientConnectionCloseCallback): void {
      this.onWebSocketServerCloseInner(callback);
    }

    onMessageReceive(callback: Callback<WebSocketMessage>): void {
      this.onMessageReceiveInner(callback);
    }

    native offWebSocketServerErrorInner(callback?: ErrorCallback): void;
    native offConnectInner(callback?: Callback<WebSocketConnection>): void;
    native offWebSocketServerCloseInner(callback?: ClientConnectionCloseCallback): void;
    native offMessageReceiveInner(callback?: Callback<WebSocketMessage>): void;

    offWebSocketServerError(callback?: ErrorCallback): void {
      if (callback === undefined) {
        this.offWebSocketServerErrorInner();
      } else {
        this.offWebSocketServerErrorInner(callback);
      }
    }

    offConnect(callback?: Callback<WebSocketConnection>): void {
      if (callback === undefined) {
        this.offConnectInner();
      } else {
        this.offConnectInner(callback);
      }
    }

    offWebSocketServerClose(callback?: ClientConnectionCloseCallback): void {
      if (callback === undefined) {
        this.offWebSocketServerCloseInner();
      } else {
        this.offWebSocketServerCloseInner(callback);
      }
    }

    offMessageReceive(callback?: Callback<WebSocketMessage>): void {
      if (callback === undefined) {
        this.offMessageReceiveInner();
      } else {
        this.offMessageReceiveInner(callback);
      }
    }
  }
}
