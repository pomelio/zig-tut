```zig
/// lib.zig

//! libxev-http: High-performance async HTTP framework for Zig
//!
//! A modern, production-ready HTTP server built on libxev for maximum performance
//! and cross-platform compatibility.
//!
//! ## Features
//! - Async event-driven architecture using libxev
//! - High-performance routing with parameter extraction
//! - Middleware support for request/response processing
//! - Memory-safe HTTP parsing and response building
//! - Cross-platform compatibility (Linux, macOS, Windows)
//! - Production-ready security features

const std = @import("std");
const xev = @import("xev");
const net = std.net;
const log = std.log;
const security = @import("security.zig");
const middleware = @import("middleware.zig");

// Version information
pub const version = "1.0.0";
pub const version_major = 1;
pub const version_minor = 0;
pub const version_patch = 0;

// Re-export commonly used types
pub const Allocator = std.mem.Allocator;
pub const ArrayList = std.ArrayList;
pub const StringHashMap = std.StringHashMap;

// Re-export core modules
pub const HttpRequest = @import("request.zig").HttpRequest;
pub const HttpMethod = @import("request.zig").HttpMethod;
pub const HttpResponse = @import("response.zig").HttpResponse;
pub const StatusCode = @import("response.zig").StatusCode;
pub const Context = @import("context.zig").Context;
pub const Router = @import("router.zig").Router;
pub const Route = @import("router.zig").Route;
pub const HandlerFn = @import("router.zig").HandlerFn;

// Re-export utility modules
pub const Buffer = @import("buffer.zig").Buffer;
pub const BufferPool = @import("buffer.zig").BufferPool;
pub const BufferPoolStats = @import("buffer.zig").BufferPoolStats;
pub const HttpConfig = @import("config.zig").HttpConfig;
pub const AppConfig = @import("config.zig").AppConfig;
pub const loadConfig = @import("config.zig").loadConfig;

// Re-export security modules
pub const Security = @import("security.zig");
pub const SecurityLimits = @import("security.zig").SecurityLimits;
pub const SecurityResult = @import("security.zig").SecurityResult;
pub const ConnectionTiming = @import("security.zig").ConnectionTiming;

// Re-export middleware modules
pub const MiddlewareFn = middleware.MiddlewareFn;
pub const NextFn = middleware.NextFn;
pub const MiddlewareChain = middleware.MiddlewareChain;
pub const Middleware = middleware.Middleware;

// Built-in middleware
pub const loggingMiddleware = middleware.loggingMiddleware;
pub const corsMiddleware = middleware.corsMiddleware;
pub const securityHeadersMiddleware = middleware.securityHeadersMiddleware;
pub const requestIdMiddleware = middleware.requestIdMiddleware;
pub const rateLimitMiddleware = middleware.rateLimitMiddleware;
pub const basicAuthMiddleware = middleware.basicAuthMiddleware;
pub const jsonBodyParserMiddleware = middleware.jsonBodyParserMiddleware;
pub const errorHandlerMiddleware = middleware.errorHandlerMiddleware;
pub const compressionMiddleware = middleware.compressionMiddleware;

/// Client connection context for handling HTTP requests
const ClientConnection = struct {
    tcp: xev.TCP,
    server: *Server,
    allocator: Allocator,
    buffer: [8192]u8,
    read_completion: xev.Completion,
    write_completion: xev.Completion,
    close_completion: xev.Completion,
    read_len: usize,
    total_read: usize,
    response_data: ?[]u8,
    is_closing: bool,
    timing: security.ConnectionTiming,
    request_buffer: std.ArrayList(u8),

    fn init(tcp: xev.TCP, server: *Server, allocator: Allocator) ClientConnection {
        return ClientConnection{
            .tcp = tcp,
            .server = server,
            .allocator = allocator,
            .buffer = undefined,
            .read_len = 0,
            .total_read = 0,
            .read_completion = .{},
            .write_completion = .{},
            .close_completion = .{},
            .response_data = null,
            .is_closing = false,
            .timing = security.ConnectionTiming.init(),
            .request_buffer = std.ArrayList(u8).init(allocator),
        };
    }

    fn deinit(self: *ClientConnection) void {
        // Clean up response data
        if (self.response_data) |data| {
            self.allocator.free(data);
        }

        // Clean up request buffer
        self.request_buffer.deinit();

        // Destroy the connection object
        self.allocator.destroy(self);
    }

    fn close(self: *ClientConnection, loop: *xev.Loop) void {
        if (self.is_closing) return;
        self.is_closing = true;

        // Release connection pool slot immediately
        self.server.connection_pool.release();

        // Gracefully close TCP connection
        self.tcp.close(loop, &self.close_completion, ClientConnection, self, closeCallback);
    }

    /// Check if connection has timed out or has processing issues
    fn checkTimeouts(self: *ClientConnection) bool {
        const result = security.checkRequestTimeouts(&self.timing, self.server.config);

        switch (result) {
            .allowed => return false,
            .connection_timeout => {
                log.warn("⏰ Connection timeout exceeded", .{});
                return true;
            },
            .idle_timeout => {
                log.warn("⏰ Idle timeout exceeded", .{});
                return true;
            },
            .processing_timeout => {
                log.warn("⏱️ Request processing timeout", .{});
                return true;
            },
            else => {
                log.warn("🚫 Request validation failed: {s}", .{security.getSecurityResultDescription(result)});
                return true;
            },
        }
    }
};

/// Server status information
pub const ServerStatus = struct {
    active_connections: u32,
    max_connections: u32,
    routes_count: u32,
};

/// Connection pool for managing active connections
const ConnectionPool = struct {
    active_connections: std.atomic.Value(u32),
    max_connections: u32,

    fn init(max_connections: u32) ConnectionPool {
        return ConnectionPool{
            .active_connections = std.atomic.Value(u32).init(0),
            .max_connections = max_connections,
        };
    }

    fn tryAcquire(self: *ConnectionPool) bool {
        while (true) {
            const current = self.active_connections.load(.acquire);
            if (current >= self.max_connections) {
                return false;
            }
            if (self.active_connections.cmpxchgWeak(current, current + 1, .acq_rel, .acquire) == null) {
                return true;
            }
        }
    }

    fn release(self: *ConnectionPool) void {
        _ = self.active_connections.fetchSub(1, .acq_rel);
    }

    fn getActiveCount(self: *ConnectionPool) u32 {
        return self.active_connections.load(.acquire);
    }
};

/// HTTP server built on libxev
pub const Server = struct {
    allocator: Allocator,
    host: []const u8,
    port: u16,
    router: *Router,
    connection_pool: ConnectionPool,
    config: HttpConfig,

    pub fn init(allocator: Allocator, host: []const u8, port: u16) !Server {
        return initWithConfig(allocator, host, port, HttpConfig{});
    }

    pub fn initWithMaxConnections(allocator: Allocator, host: []const u8, port: u16, max_connections: u32) !Server {
        var config = HttpConfig{};
        config.max_connections = max_connections;
        return initWithConfig(allocator, host, port, config);
    }

    pub fn initWithConfig(allocator: Allocator, host: []const u8, port: u16, config: HttpConfig) !Server {
        const router = try Router.init(allocator);

        return Server{
            .allocator = allocator,
            .host = host,
            .port = port,
            .router = router,
            .connection_pool = ConnectionPool.init(@intCast(config.max_connections)),
            .config = config,
        };
    }

    pub fn deinit(self: *Server) void {
        self.router.deinit();
        self.allocator.destroy(self.router);
    }

    /// Add a GET route
    pub fn get(self: *Server, path: []const u8, handler: HandlerFn) !*Route {
        return try self.router.get(path, handler);
    }

    /// Add a POST route
    pub fn post(self: *Server, path: []const u8, handler: HandlerFn) !*Route {
        return try self.router.post(path, handler);
    }

    /// Add a PUT route
    pub fn put(self: *Server, path: []const u8, handler: HandlerFn) !*Route {
        return try self.router.put(path, handler);
    }

    /// Add a DELETE route
    pub fn delete(self: *Server, path: []const u8, handler: HandlerFn) !*Route {
        return try self.router.delete(path, handler);
    }

    /// Add global middleware that applies to all routes
    pub fn use(self: *Server, name: []const u8, middleware_fn: MiddlewareFn) !void {
        return try self.router.use(name, middleware_fn);
    }

    /// Check if thread pool is enabled
    pub fn hasThreadPool(self: *Server) bool {
        return self.config.enable_thread_pool;
    }

    /// Get server status information
    pub fn getStatus(self: *Server) ServerStatus {
        return ServerStatus{
            .active_connections = self.connection_pool.getActiveCount(),
            .max_connections = self.connection_pool.max_connections,
            .routes_count = @intCast(self.router.routes.items.len),
        };
    }

    /// Start the HTTP server with complete HTTP processing
    pub fn listen(self: *Server) !void {
        log.info("🚀 Starting libxev-http server on {s}:{}", .{ self.host, self.port });
        log.info("🎯 Routes registered: {}", .{self.router.routes.items.len});
        log.info("🔗 Max connections: {}", .{self.connection_pool.max_connections});

        // Show registered routes
        for (self.router.routes.items) |route| {
            log.info("   📍 {any} {s}", .{ route.method, route.pattern });
        }

        // Initialize libxev thread pool if enabled
        var libxev_thread_pool: ?xev.ThreadPool = null;
        if (self.config.enable_thread_pool) {
            libxev_thread_pool = xev.ThreadPool.init(.{
                .max_threads = if (self.config.thread_pool_size == 0)
                    @max(1, @as(u32, @intCast(std.Thread.getCpuCount() catch 4)))
                else
                    self.config.thread_pool_size,
                .stack_size = self.config.thread_pool_stack_size,
            });
            log.info("🧵 libxev ThreadPool initialized with {} max threads", .{libxev_thread_pool.?.max_threads});
        }
        defer if (libxev_thread_pool) |*pool| pool.deinit();

        // Initialize libxev event loop with optional thread pool
        var loop = try xev.Loop.init(.{
            .thread_pool = if (libxev_thread_pool) |*pool| pool else null,
        });
        defer loop.deinit();

        // Create TCP server
        const address = try net.Address.parseIp(self.host, self.port);
        var tcp_server = try xev.TCP.init(address);

        // Bind and listen
        try tcp_server.bind(address);
        try tcp_server.listen(128);

        log.info("✅ Server listening on http://{s}:{}", .{ self.host, self.port });
        log.info("🔄 Server running... Press Ctrl+C to stop", .{});

        // Start accepting connections
        var accept_completion: xev.Completion = .{};
        tcp_server.accept(&loop, &accept_completion, Server, self, acceptCallback);

        // Run the event loop
        try loop.run(.until_done);
    }
};

/// Callback for closing connections
fn closeCallback(
    userdata: ?*ClientConnection,
    loop: *xev.Loop,
    completion: *xev.Completion,
    tcp: xev.TCP,
    result: xev.CloseError!void,
) xev.CallbackAction {
    _ = loop;
    _ = completion;
    _ = tcp;
    const client_conn = userdata.?;

    result catch |err| {
        log.warn("Connection close error (expected): {any}", .{err});
    };

    log.info("🔒 Connection closed", .{});
    client_conn.deinit();
    return .disarm;
}

/// Callback for accepting new connections
fn acceptCallback(
    userdata: ?*Server,
    loop: *xev.Loop,
    completion: *xev.Completion,
    result: xev.AcceptError!xev.TCP,
) xev.CallbackAction {
    _ = completion;
    const server = userdata.?;

    const client_tcp = result catch |err| {
        log.err("Failed to accept connection: {any}", .{err});
        return .rearm;
    };

    // Check if connection pool is full
    if (!server.connection_pool.tryAcquire()) {
        log.warn("⚠️  Connection pool full, rejecting connection. Active: {}", .{server.connection_pool.getActiveCount()});
        return .rearm;
    }

    log.info("📥 Accepted new connection (Active: {})", .{server.connection_pool.getActiveCount()});

    // Create client connection
    const client_conn = server.allocator.create(ClientConnection) catch |err| {
        log.err("Failed to allocate client connection: {any}", .{err});
        server.connection_pool.release();
        return .rearm;
    };

    client_conn.* = ClientConnection.init(client_tcp, server, server.allocator);

    // Start reading HTTP request
    // Use client_conn.read_completion
    client_tcp.read(loop, &client_conn.read_completion, .{ .slice = &client_conn.buffer }, ClientConnection, client_conn, readCallback);

    return .rearm;
}

/// Callback for reading HTTP request data
fn readCallback(
    userdata: ?*ClientConnection,
    loop: *xev.Loop,
    completion: *xev.Completion,
    tcp: xev.TCP,
    buffer: xev.ReadBuffer,
    result: xev.ReadError!usize,
) xev.CallbackAction {
    _ = completion;
    _ = tcp;
    _ = buffer;
    const client_conn = userdata.?;

    const bytes_read = result catch |err| {
        log.err("Failed to read from connection: {any}", .{err});
        client_conn.close(loop);
        return .disarm;
    };

    if (bytes_read == 0) {
        log.info("📤 Connection closed by client", .{});
        client_conn.close(loop);
        return .disarm;
    }

    // Update timing information
    client_conn.timing.updateReadTime();
    client_conn.total_read += bytes_read;

    // Check for timeouts and slow attacks
    if (client_conn.checkTimeouts()) {
        log.warn("🚫 Closing connection due to timeout or slow attack", .{});
        client_conn.close(loop);
        return .disarm;
    }

    // Check for reasonable request size limits - allow for large bodies but prevent abuse
    const max_reasonable_request = client_conn.server.config.max_body_size + 64 * 1024; // body + 64KB for headers
    if (client_conn.total_read > max_reasonable_request) {
        log.warn("🚫 Request too large: {} bytes (limit: {} bytes)", .{ client_conn.total_read, max_reasonable_request });
        sendErrorResponse(client_conn, loop, .payload_too_large) catch {};
        return .disarm;
    }

    log.info("📨 Received {} bytes (total: {})", .{ bytes_read, client_conn.total_read });

    // Append data to request buffer
    client_conn.request_buffer.appendSlice(client_conn.buffer[0..bytes_read]) catch |err| {
        log.err("Failed to append to request buffer: {any}", .{err});
        sendErrorResponse(client_conn, loop, .internal_server_error) catch {};
        return .disarm;
    };

    // Check if we have complete headers
    if (!client_conn.timing.headers_complete) {
        if (std.mem.indexOf(u8, client_conn.request_buffer.items, "\r\n\r\n")) |_| {
            // Parse Content-Length if present
            const content_length = security.parseContentLength(client_conn.request_buffer.items);
            client_conn.timing.setHeadersComplete(content_length);
        }
    }

    // Update body length tracking
    if (client_conn.timing.headers_complete) {
        const header_end = std.mem.indexOf(u8, client_conn.request_buffer.items, "\r\n\r\n");
        const body_length = if (header_end) |end_pos|
            client_conn.request_buffer.items.len - (end_pos + 4)
        else
            0;
        client_conn.timing.updateBodyLength(body_length);
    }

    // Try to process the request if we have enough data
    const should_process = blk: {
        if (!client_conn.timing.headers_complete) {
            break :blk false; // Need complete headers
        }

        if (client_conn.timing.expected_body_length) |expected| {
            break :blk client_conn.timing.received_body_length >= expected; // Need complete body
        }

        break :blk true; // No body expected, headers are enough
    };

    if (should_process) {
        // Process the complete HTTP request
        processHttpRequestFromBuffer(client_conn, loop) catch |err| {
            log.err("Failed to process HTTP request: {any}", .{err});
            sendErrorResponse(client_conn, loop, .internal_server_error) catch {};
        };
        return .disarm;
    } else {
        // Continue reading more data
        client_conn.tcp.read(loop, &client_conn.read_completion, .{ .slice = &client_conn.buffer }, ClientConnection, client_conn, readCallback);
        return .disarm;
    }
}

/// Process HTTP request from accumulated buffer and send response
fn processHttpRequestFromBuffer(client_conn: *ClientConnection, loop: *xev.Loop) !void {
    const request_data = client_conn.request_buffer.items;

    // Parse HTTP request
    var request = HttpRequest.parseFromBuffer(client_conn.allocator, request_data, client_conn.server.config) catch |err| {
        log.err("Failed to parse HTTP request: {any}", .{err});
        try sendErrorResponse(client_conn, loop, .bad_request);
        return;
    };
    defer request.deinit();

    log.info("📋 Processing {any} {s}", .{ request.method, request.path });

    // Create HTTP response
    var response = HttpResponse.init(client_conn.allocator);
    defer response.deinit();

    // Create context
    var ctx = Context.init(client_conn.allocator, &request, &response);
    defer ctx.deinit();

    // Handle request with router
    client_conn.server.router.handleRequest(&ctx) catch |err| {
        log.err("Router error: {any}", .{err});
        switch (err) {
            error.NotFound => {
                ctx.status(.not_found);
                try ctx.json("{\"error\":\"Not Found\",\"message\":\"The requested resource was not found\"}");
            },
            error.InvalidMethod => {
                ctx.status(.method_not_allowed);
                try ctx.json("{\"error\":\"Method Not Allowed\",\"message\":\"The HTTP method is not supported\"}");
            },
            else => {
                ctx.status(.internal_server_error);
                try ctx.json("{\"error\":\"Internal Server Error\",\"message\":\"An unexpected error occurred\"}");
            },
        }
    };

    // Build and send response
    const response_data = try response.build();

    log.info("📤 Sending {} bytes response", .{response_data.len});
    try sendResponse(client_conn, loop, response_data);
}

/// Process HTTP request and send response (legacy function for compatibility)
fn processHttpRequest(client_conn: *ClientConnection, loop: *xev.Loop) !void {
    // For legacy compatibility, copy buffer data to request_buffer and process
    try client_conn.request_buffer.appendSlice(client_conn.buffer[0..client_conn.read_len]);
    return processHttpRequestFromBuffer(client_conn, loop);
}

/// Send HTTP response to client
fn sendResponse(client_conn: *ClientConnection, loop: *xev.Loop, response_data: []u8) !void {
    // Use client_conn.write_completion
    // Store response_data in ClientConnection to keep it alive
    client_conn.response_data = response_data;
    client_conn.tcp.write(loop, &client_conn.write_completion, .{ .slice = response_data }, ClientConnection, client_conn, writeCallback);

    // Run one iteration to complete the write
}

/// Callback for writing response data
fn writeCallback(
    userdata: ?*ClientConnection,
    loop: *xev.Loop,
    completion: *xev.Completion,
    tcp: xev.TCP,
    buffer: xev.WriteBuffer,
    result: xev.WriteError!usize,
) xev.CallbackAction {
    _ = completion;
    _ = tcp;
    _ = buffer;
    const client_conn = userdata.?;

    const bytes_written = result catch |err| {
        log.err("Failed to write response: {any}", .{err});
        client_conn.close(loop);
        return .disarm;
    };

    log.info("✅ Sent {} bytes response", .{bytes_written});

    // Close connection after sending response
    client_conn.close(loop);
    return .disarm;
}

/// Send error response to client
fn sendErrorResponse(client_conn: *ClientConnection, loop: *xev.Loop, status: StatusCode) !void {
    var response = HttpResponse.init(client_conn.allocator);
    defer response.deinit();

    response.status = status;
    try response.setHeader("Content-Type", "application/json");
    try response.setHeader("Connection", "close");

    const error_json = try std.fmt.allocPrint(client_conn.allocator, "{{\"error\":\"{s}\",\"code\":{}}}", .{ status.toString(), @intFromEnum(status) });
    defer client_conn.allocator.free(error_json);

    try response.setBody(error_json);

    const response_data = try response.build();

    try sendResponse(client_conn, loop, response_data);
}

/// Create a new HTTP server
pub fn createServer(allocator: Allocator, host: []const u8, port: u16) !Server {
    return try Server.init(allocator, host, port);
}

/// Create a new HTTP server with custom max connections
pub fn createServerWithMaxConnections(allocator: Allocator, host: []const u8, port: u16, max_connections: u32) !Server {
    return try Server.initWithMaxConnections(allocator, host, port, max_connections);
}

/// Create a new HTTP server with custom configuration
pub fn createServerWithConfig(allocator: Allocator, host: []const u8, port: u16, config: HttpConfig) !Server {
    return try Server.initWithConfig(allocator, host, port, config);
}

// Tests
test "library exports" {
    const testing = std.testing;
    try testing.expect(version_major == 1);
    try testing.expect(version_minor == 0);
    try testing.expect(version_patch == 0);
    try testing.expectEqualStrings("1.0.0", version);
}

test "server creation and routes" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var server = try createServer(allocator, "127.0.0.1", 8080);
    defer server.deinit();

    try testing.expectEqualStrings("127.0.0.1", server.host);
    try testing.expect(server.port == 8080);

    // Test adding routes
    const testHandler = struct {
        fn handler(ctx: *Context) !void {
            _ = ctx;
        }
    }.handler;

    _ = try server.get("/", testHandler);
    _ = try server.post("/api/users", testHandler);

    try testing.expect(server.router.routes.items.len == 2);
}

test "module integration" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Test request parsing
    const raw_request = "GET /hello HTTP/1.1\r\nHost: localhost\r\n\r\n";
    const config = HttpConfig{};
    var request = try HttpRequest.parseFromBuffer(allocator, raw_request, config);
    defer request.deinit();

    // Test response building
    var response = HttpResponse.init(allocator);
    defer response.deinit();

    // Test context
    var ctx = Context.init(allocator, &request, &response);
    defer ctx.deinit();

    try ctx.json("{\"message\":\"test\"}");

    try testing.expectEqualStrings("GET", request.method);
    try testing.expectEqualStrings("/hello", request.path);
    try testing.expect(response.body != null);
}

```

Excellent! Let's move from the "recipe book" (`build.zig`) to the "main kitchen" itself. This file, `lib.zig`, is the heart of our web server library. It's where all the core components are assembled and managed.

---

### Welcome, Class! Inside the Engine Room: `lib.zig`

Yesterday, we looked at the `build.zig` file, which was our recipe book for compiling the project. Today, we're stepping into the main factory, the engine room where all the work happens: `lib.zig`.

This file has two primary jobs:
1.  **It defines the main `Server` and how it handles connections.** This is the core logic.
2.  **It acts as the main "front door" or "lobby" for our entire library.** It gathers all the important pieces from other files (`request.zig`, `response.zig`, etc.) and presents them in one convenient place for the person using our library.

Let's start at the top.

---

### Part 1: The Library's "Lobby" (Imports & Re-exports)

```zig
//! libxev-http: High-performance async HTTP framework for Zig
//! ... (documentation comments)

const std = @import("std");
const xev = @import("xev");
// ... other imports

// Version information
pub const version = "1.0.0";
// ...

// Re-export commonly used types
pub const Allocator = std.mem.Allocator;
// ...

// Re-export core modules
pub const HttpRequest = @import("request.zig").HttpRequest;
pub const HttpResponse = @import("response.zig").HttpResponse;
// ... (many more re-exports)
```

The first thing you'll notice after the initial documentation comments (`//!`) is a huge block of `pub const ...` lines. This is a very important and friendly design pattern in Zig.

Think of our library as a large company building with many different departments on different floors (e.g., the `request.zig` file is the "Incoming Mail Department," `response.zig` is the "Outgoing Mail Department").

Instead of making a visitor (the programmer using our library) run around to all these different files to get what they need, we've created a **central lobby** right here in `lib.zig`.

These `pub const` lines are like a directory in the lobby. We're saying:
*   "Looking for `HttpRequest`? You don't have to know it's in `request.zig`. You can just get it right here from the main library."
*   "Need a `Router`? It's right here."
*   "Looking for some built-in `loggingMiddleware`? We've brought it out to the front for you."

This is called **re-exporting**. It makes our library much cleaner and easier to use. The user only needs to `@import` this one file to get access to all the most important tools.

---

### Part 2: The Core Components (Structs)

Now we get to the main machinery. There are three key data structures, or `struct`s, that work together. Let's use an analogy of a busy restaurant.

#### `ClientConnection`: The Waiter

```zig
const ClientConnection = struct {
    tcp: xev.TCP,
    server: *Server,
    allocator: Allocator,
    buffer: [8192]u8,
    // ... other fields
};
```
This struct represents **one single client** connected to our server. Think of this as a **waiter** assigned to a specific table.

*   `tcp: xev.TCP`: This is the direct phone line to the customer (the TCP connection).
*   `server: *Server`: A reference back to the "Restaurant Manager" so the waiter knows who they work for.
*   `allocator: Allocator`: The waiter's budget for things like taking notes or preparing the bill.
*   `buffer`: The waiter's notepad, where they write down the customer's order as it comes in.
*   `timing`: A stopwatch to make sure a customer doesn't take forever to order (this prevents certain types of attacks).
*   `init()` and `deinit()`: These functions are like the waiter setting up the table for a new customer and clearing it after they leave.

#### `ConnectionPool`: The Host/Hostess

```zig
const ConnectionPool = struct {
    active_connections: std.atomic.Value(u32),
    max_connections: u32,
};
```
This struct's job is to make sure our restaurant doesn't get overcrowded. It's the **host or hostess** at the front door.

*   `max_connections`: The fire code limit for our restaurant. We can't have more customers than this.
*   `active_connections`: The current number of customers in the restaurant. (It's `atomic` which is a special type that ensures this count is accurate even when many waiters try to update it at the exact same time).
*   `tryAcquire()`: This is like asking the hostess, "Is there a free table?" It returns `true` if yes, `false` if the restaurant is full.
*   `release()`: This is the waiter telling the hostess, "My table is free now!"

#### `Server`: The Restaurant Manager

```zig
pub const Server = struct {
    allocator: Allocator,
    host: []const u8,
    port: u16,
    router: *Router,
    connection_pool: ConnectionPool,
    config: HttpConfig,
};
```
This is the big boss, the **Restaurant Manager**. It holds everything together.

*   `host` and `port`: The restaurant's address.
*   `router`: The **menu**. This is the component that knows what to do for each request (e.g., if a customer asks for `/users`, the router knows to call the "get users" chef).
*   `connection_pool`: The manager's connection to the hostess at the front door.
*   `get()`, `post()`, `use()`: These are methods the owner uses to tell the manager to add new items to the menu (the router).
*   `listen()`: This is the most important function. It's the manager shouting, **"We're open for business!"** and starting the whole process.

---

### Part 3: The Asynchronous Magic (Callbacks)

This is the most important concept to understand. Our server is **asynchronous** or **event-driven**.

A *synchronous* restaurant would have the manager constantly running to the front door shouting "ANYONE THERE YET? ANYONE THERE YET?". This is very inefficient.

Our *asynchronous* restaurant works with a system of bells.
1.  The manager tells the front door: "Ring a bell when a customer arrives." (`tcp_server.accept`)
2.  The manager goes off and does other things.
3.  When a customer arrives, a bell rings, and a special function called a **callback** is automatically run.

Let's follow the lifecycle of one request:

#### Step 1: `acceptCallback`
*   **The Event:** A new customer walks in the door. The `accept` bell rings!
*   **The Action:** The `acceptCallback` function runs.
    *   It first asks the `connection_pool` (the hostess), "Do we have a free table?"
    *   If yes, it creates a new `ClientConnection` (assigns a new waiter to the table).
    *   It then tells the new waiter, "Ring a bell for me as soon as this customer starts speaking." (`client_tcp.read`).

#### Step 2: `readCallback`
*   **The Event:** The customer starts giving their order (sends HTTP request data). The `read` bell rings!
*   **The Action:** The `readCallback` function runs for that specific `ClientConnection` (waiter).
    *   It writes down what the customer said into its `buffer` (notepad).
    *   It checks, "Is this the full order, or are they still talking?" It looks for the special `\r\n\r\n` sequence that marks the end of the HTTP headers.
    *   If the order isn't complete, it just says, "Okay, keep listening."
    *   If the order *is* complete, it calls `processHttpRequestFromBuffer` to send the order to the kitchen.

#### Step 3: `processHttpRequestFromBuffer` (The Kitchen)
*   This isn't a callback, but it's the next step.
*   It takes the raw text from the waiter's notepad.
*   It parses it into a structured `HttpRequest` object.
*   It looks at the request path (e.g., `/users`) and gives it to the `router` (the menu).
*   The router finds the correct chef (`HandlerFn`) to handle this specific dish.
*   The chef prepares the meal and puts it into an `HttpResponse` object.
*   Finally, it tells a waiter to deliver the food by calling `sendResponse`.

#### Step 4: `writeCallback`
*   **The Event:** The waiter has successfully delivered the food to the customer. The `write` bell rings!
*   **The Action:** The `writeCallback` function runs.
    *   It logs that the response was sent successfully.
    *   Since the transaction is complete, it tells the customer's connection to close (`client_conn.close`).

#### Step 5: `closeCallback`
*   **The Event:** The connection has been fully closed. The `close` bell rings!
*   **The Action:** The `closeCallback` function runs.
    *   It cleans up everything associated with that waiter and table (`client_conn.deinit()`).
    *   Crucially, the waiter also tells the hostess their table is now free (`self.server.connection_pool.release()`, which happens inside the `close` function).

---

### Part 4: The Self-Checks (Tests)

```zig
test "library exports" { ... }
test "server creation and routes" { ... }
test "module integration" { ... }
```
At the very bottom of the file, you see `test` blocks. These are built-in checks to make sure our kitchen is working correctly.
*   `test "server creation and routes"` is like checking that the manager can correctly add items to the menu.
*   `test "module integration"` is a quick check to ensure the whole process—from taking an order to preparing a response—works on a small scale.

### Conclusion

This `lib.zig` file is the heart of the server. It uses a series of structs to manage the server's state and an asynchronous, event-driven model with callbacks to handle many connections efficiently without getting stuck waiting for any single one. It's like a well-run restaurant where the staff doesn't stand around waiting, but instead responds instantly when a bell rings, signaling that their attention is needed.


好的，我们来扮演老师和学生，一起深入研究这个 `lib.zig` 文件。这个文件是整个 Web 框架的心脏，所有的核心逻辑都在这里。

---

### 各位同学，欢迎来到引擎室：`lib.zig` 文件详解

昨天我们学习了 `build.zig`，那是我们项目的“菜谱”。今天，我们要走进真正的“厨房”或者说“引擎室”——`lib.zig` 文件。

这个文件主要有两个职责：

1.  **定义核心的 `Server`（服务器）以及它如何处理网络连接。** 这是最关键的运行逻辑。
2.  **充当整个库的“大门”或“前台”。** 它把其他文件（如 `request.zig`, `response.zig`）中最重要的部分集中起来，方便使用这个库的程序员调用。

我们从头开始看。

---

### 第一部分：库的“前台大厅”（导入与重导出）

```zig
//! libxev-http: High-performance async HTTP framework for Zig
//! ... (这些是文档注释)

const std = @import("std");
const xev = @import("xev");
// ... 其他导入

// Version information
pub const version = "1.0.0";
// ...

// Re-export commonly used types (重导出常用类型)
pub const Allocator = std.mem.Allocator;
// ...

// Re-export core modules (重导出核心模块)
pub const HttpRequest = @import("request.zig").HttpRequest;
pub const HttpResponse = @import("response.zig").HttpResponse;
// ... (后面还有很多类似的行)
```

在文件的开头，你会看到一大片 `pub const ...`。这是一个在 Zig 中非常友好且重要的设计模式，我们称之为 **“重导出”（Re-exporting）**。

想象一下我们的库是一个有多层多部门的大公司（比如 `request.zig` 是“收发室”，`response.zig` 是“外联部”）。

我们不希望一个访客（也就是使用我们库的程序员）为了找不同的工具而跑遍所有部门。所以，我们在这个 `lib.zig` 文件里建立了一个 **“中央前台”**。

这些 `pub const` 行就像是前台的指示牌：
*   “想找 `HttpRequest` 吗？你不用去 `request.zig` 文件里找，直接从我这里（`lib.zig`）拿就行。”
*   “需要 `Router` 吗？给你，在这里。”

这样做让我们的库对使用者来说非常干净、方便。用户只需要 `@import` 这一个 `lib.zig` 文件，就能获得所有最核心的工具。

---

### 第二部分：核心组件（Struct 结构体）

现在我们来看看驱动服务器运转的核心机械。这里有三个关键的结构体，我们可以用一个**繁忙的餐厅**来比喻它们。

#### 1. `ClientConnection`：服务员

```zig
const ClientConnection = struct {
    tcp: xev.TCP,
    server: *Server,
    allocator: Allocator,
    buffer: [8192]u8,
    // ... 其他字段
};
```

这个结构体代表**一个连接到服务器的独立客户端**。你可以把它想象成一个**被指派到特定餐桌的“服务员”**。

*   `tcp: xev.TCP`: 这是与顾客的**直接电话线**（TCP 连接）。
*   `server: *Server`: 指向“餐厅经理”，这样服务员才知道为谁工作。
*   `allocator: Allocator`: 服务员的“经费”，用来记录点单、准备账单等需要内存的操作。
*   `buffer`: 服务员的**点餐本**，用来记录顾客说的每一句话（请求数据）。
*   `timing`: 一个秒表，确保顾客不会点一个菜点半天（这可以防止慢速攻击）。

#### 2. `ConnectionPool`：餐厅领位员

```zig
const ConnectionPool = struct {
    active_connections: std.atomic.Value(u32),
    max_connections: u32,
};
```

这个结构体的唯一工作就是**确保餐厅不会人满为患**。它就像是站在门口的**“领位员”**。

*   `max_connections`: 餐厅的消防规定人数上限。
*   `active_connections`: 当前在餐厅里的客人数量。它是一个 `atomic`（原子）类型，确保即使很多服务员同时更新这个数字，它也总是准确的。
*   `tryAcquire()`: 相当于问领位员：“还有空桌吗？” 如果有，返回 `true`；如果满了，返回 `false`。
*   `release()`: 服务员告诉领位员：“我这桌客人走了！”

#### 3. `Server`：餐厅经理

```zig
pub const Server = struct {
    // ...
    router: *Router,
    connection_pool: ConnectionPool,
    // ...
};
```
这是总指挥——**“餐厅经理”**。它把所有部分组织在一起。

*   `router`: 餐厅的**菜单**。它知道每个请求该如何处理（例如，顾客点 `/users`，菜单知道该找哪个厨师）。
*   `connection_pool`: 经理和门口领位员的联系方式。
*   `listen()`: 这是最重要的方法。它相当于经理大喊一声：**“开门营业！”**，然后整个餐厅就开始运作了。

---

### 第三部分：异步的魔法（回调函数与 xev）

这是最核心、也最需要理解的部分。我们的服务器是**异步的（asynchronous）**，或者叫**事件驱动的（event-driven）**。

一个**同步**的餐厅经理会不停地跑到门口喊：“来客人了吗？来客人了吗？” 这非常低效。

我们的**异步**餐厅经理则使用一套**“铃铛系统”**。

1.  经理告诉门口：“有客人来的时候，**摇一下铃铛**。”
2.  然后经理就去忙别的事了。
3.  当客人真的来了，铃铛响起，一个特殊的函数——我们称之为**回调函数（Callback）**——就会被自动执行。

这里的 `xev` 库就是为我们提供这套“铃铛系统”的。让我们跟踪一个请求的完整生命周期，并重点关注 `xev` 的调用。

#### `listen()` 函数：开门营业

```zig
pub fn listen(self: *Server) !void {
    // ... 省略日志打印 ...

    var loop = try xev.Loop.init(...); // 1. 准备好事件循环（“经理的大脑”）
    defer loop.deinit();

    var tcp_server = try xev.TCP.init(address); // 2. 准备好TCP服务器（“餐厅大门”）
    try tcp_server.bind(address);
    try tcp_server.listen(128); // 3. 开始监听（“把门打开”）

    // ...

    var accept_completion: xev.Completion = .{};
    tcp_server.accept(&loop, &accept_completion, Server, self, acceptCallback); // 4. 设置铃铛

    try loop.run(.until_done); // 5. 开始工作！（“经理开始听所有铃铛的声音”）
}
```

第4步是第一个关键的 `xev` 调用：
*   `tcp_server.accept(...)`: 这句话的意思是：“嘿，`xev`，请帮我监听 `tcp_server` 这个大门。”
*   `&loop`: 在哪个事件循环上监听。
*   `Server, self, acceptCallback`: **这是魔法的核心！** 它告诉 `xev`：“当一个新连接到来时（事件发生时），请调用 `acceptCallback` 这个函数，并把 `self`（也就是 `Server` 经理对象）作为上下文信息（`userdata`）传给它。”

#### `acceptCallback` 函数：客人进门

当一个新连接真的到来时，`xev` 会自动调用这个函数。

```zig
fn acceptCallback(...) xev.CallbackAction {
    // ...
    const client_tcp = result catch { ... }; // 1. 拿到与新客人的“电话线”

    if (!server.connection_pool.tryAcquire()) { // 2. 问领位员是否满座
        // ... 满了就拒绝
    }

    // 3. 分配一个“服务员”(ClientConnection)
    const client_conn = ...;
    client_conn.* = ClientConnection.init(client_tcp, server, server.allocator);

    // 4. 设置下一个铃铛！
    client_tcp.read(loop, &client_conn.read_completion, .{ .slice = &client_conn.buffer }, ClientConnection, client_conn, readCallback);

    return .rearm; // 5. 返回 .rearm
}
```

第4步是第二个关键的 `xev` 调用：
*   `client_tcp.read(...)`: 经理对新来的服务员说：“注意听这位客人点餐。当他开始说话（发送数据）时，摇一下铃铛。”
*   `.slice = &client_conn.buffer`: 把客人说的话（数据）记录到这位服务员的点餐本 (`buffer`) 里。
*   `ClientConnection, client_conn, readCallback`: 告诉 `xev`：“当数据传来时，请调用 `readCallback` 函数，并把 `client_conn`（这位服务员）作为上下文传给它。”

第5步的 `return .rearm;` 也很重要。它告诉 `xev`：“这次的客人我处理好了，请**重新部署（re-arm）**这个 `accept` 铃铛，我还要继续接待下一位客人。”

#### `readCallback` 函数：客人点餐

当客户端发送数据时，`xev` 会调用这个函数。

```zig
fn readCallback(...) xev.CallbackAction {
    // ...
    const bytes_read = result catch { ... }; // 1. 收到客人说的话（数据）

    if (bytes_read == 0) { // 2. 如果客人挂了电话（连接关闭）
        client_conn.close(loop); // 就结束服务
        return .disarm;
    }

    // 3. 把数据追加到完整的点餐记录(request_buffer)里
    // ...

    // 4. 检查客人是否说完了完整的一句话（HTTP请求是否完整）
    if (should_process) {
        // 5a. 如果说完了，把订单交给厨房处理
        processHttpRequestFromBuffer(client_conn, loop) catch { ... };
        return .disarm; // 订单已接收，这个“读”的任务完成了，解除部署
    } else {
        // 5b. 如果没说完，设置同一个铃铛，继续听
        client_conn.tcp.read(loop, &client_conn.read_completion, ...);
        return .disarm; // 旧的“读”任务完成，但我们马上设了个新的，效果类似重新部署
    }
}
```
`return .disarm;` 的意思是：“这次的‘读’事件我处理完了，请**解除部署（disarm）**这个铃铛。我不需要你再为**这次**读操作通知我了。” （如果需要继续读，我们会手动设置一个新的 `read` 任务，就像 `5b` 那样）。

#### `processHttpRequestFromBuffer` 函数：厨房处理订单

这个函数不是回调，而是我们自己的逻辑。它解析请求，通过 `router`（菜单）找到对应的处理函数（厨师），生成 `HttpResponse`（菜品），然后调用 `sendResponse` 上菜。

#### `sendResponse` & `writeCallback` 函数：上菜与确认

`sendResponse` 函数里有第三个关键的 `xev` 调用：
```zig
fn sendResponse(...) {
    // ...
    client_conn.response_data = response_data; // 重要：先把菜端在托盘上，防止被回收
    client_conn.tcp.write(loop, &client_conn.write_completion, .{ .slice = response_data }, ClientConnection, client_conn, writeCallback);
}
```
*   `client_conn.tcp.write(...)`: “嘿，`xev`，请把这份 `response_data`（菜）发给客人。发送**完成**后，请摇一下铃铛，调用 `writeCallback` 函数。”

当数据发送完毕后，`writeCallback` 被调用：
```zig
fn writeCallback(...) xev.CallbackAction {
    // ...
    log.info("✅ Sent {} bytes response", .{bytes_written}); // 确认菜已送到

    // 上完菜，服务结束
    client_conn.close(loop);
    return .disarm; // “写”任务完成，解除部署
}
```
#### `closeCallback` 函数：客人离席

`writeCallback` 调用 `client_conn.close(loop)`，而 `close` 函数内部会设置最后一个铃铛：
```zig
fn close(...) {
    // ...
    self.tcp.close(loop, &self.close_completion, ClientConnection, self, closeCallback);
}
```
*   `self.tcp.close(...)`: “嘿 `xev`，请关闭这个连接。当**完全关闭**后，请摇铃，调用 `closeCallback`。”

当连接彻底断开后，`closeCallback` 被调用，它会执行最终的清理工作，比如释放服务员 `client_conn` 占用的所有内存 (`client_conn.deinit()`)。

---

### 总结

这个 `lib.zig` 文件通过几个核心的 `struct` 来管理状态，并利用 `xev` 库提供的**事件循环和回调机制**，构建了一个高效的异步服务器。

整个流程就像一个高度协同的餐厅：
1.  `listen`：餐厅开门，经理开始关注大门的 `accept` 铃铛。
2.  `acceptCallback`：客人进门，分配一个服务员，并让服务员关注客人的 `read` 铃铛。
3.  `readCallback`：客人点餐，服务员记录，点完后把订单送去厨房。
4.  `processHttpRequest...`：厨房做菜。
5.  `sendResponse`：服务员上菜，并关注 `write` 铃铛，确认客人收到。
6.  `writeCallback`：客人收到菜，服务员开始清理桌面（`close`）。
7.  `closeCallback`：客人离席，服务员和桌子被完全释放，可以服务下一位客人。

整个过程，经理（主线程）从不等待任何一个客人，他只响应各种“铃铛”声，因此可以同时为成千上万的客人提供高效服务。这就是异步编程的威力！


cmpxchgWeak 为什么不直接用 fetchAdd ？

这是一个极其深刻和出色的问题！它直接触及了并发编程中算法设计的核心。你问到了点子上。

为什么在 tryAcquire 中不直接用 fetchAdd(1, .acq_rel) 而是用一个看起来更复杂的 cmpxchgWeak 循环呢？

简短的回答是：我们需要在增加计数值之前，先做一个检查（if (current >= self.max_connections)）。fetchAdd 无法将这个检查和增加操作绑定成一个原子步骤。

详细解析：原子操作的“不可分割性”

我们再回顾一下“原子”的定义：不可分割。

fetchAdd(1, ...) 是一个单一的、原子的操作。它的全部职责就是：“把值加1”。它做得非常出色，但也就仅此而已。

我们的 tryAcquire 逻辑需要做两件事：

检查：当前连接数是否小于最大限制？

增加：如果小于，就把连接数加1。

如果我们尝试用 fetchAdd 来实现，代码可能会像这样（这是错误示范！）：

code
Zig
download
content_copy
expand_less

// 错误示范：无法工作的 tryAcquire
fn tryAcquire_WRONG(self: *ConnectionPool) bool {
    // 第一步：先读取当前值
    const current = self.active_connections.load(.acquire);

    // 第二步：检查
    if (current >= self.max_connections) {
        return false;
    }

    // 第三步：增加
    // 问题来了！
    _ = self.active_connections.fetchAdd(1, .acq_rel);

    return true;
}

这段代码存在一个巨大的竞态条件（Race Condition），我们用一个场景来说明：

假设 max_connections 是 100。

线程A 执行到第一步，读取 current 为 99。

线程B 也执行到第一步，也读取 current 为 99。

线程A 执行第二步，99 < 100，检查通过。

线程B 也执行第二步，99 < 100，检查也通过。

线程A 执行第三步，调用 fetchAdd，active_connections 变成了 100。

线程B 也执行第三步，调用 fetchAdd，active_connections 变成了 101！

灾难发生了！ 我们突破了 max_connections 的限制。服务器的逻辑被破坏了。

问题就出在**“检查”和“增加”这两个步骤不是原子的**。在它们之间存在一个时间窗口，其他线程可以趁虚而入。

cmpxchg 循环的威力：将“检查”与“修改”捆绑

现在，我们再回头看 cmpxchgWeak 循环的实现：

code
Zig
download
content_copy
expand_less
IGNORE_WHEN_COPYING_START
IGNORE_WHEN_COPYING_END
fn tryAcquire(self: *ConnectionPool) bool {
    while (true) {
        // 1. 读取当前值 (我们的“猜测”)
        const current = self.active_connections.load(.acquire);

        // 2. 基于猜测进行检查
        if (current >= self.max_connections) {
            return false;
        }

        // 3. 尝试原子性地“确认猜测并修改”
        if (self.active_connections.cmpxchgWeak(current, current + 1, ...) == null) {
            // 成功！
            return true;
        }
        // 如果失败，循环会立即重试
    }
}

这个循环巧妙地解决了问题。cmpxchgWeak 这个操作本身就包含了**“检查（比较）”** 和 “修改（交换）”。

让我们用同样的场景再走一遍流程：

max_connections 是 100。active_connections 当前是 99。

线程A 进入循环：

load 得到 current 是 99。

检查 99 < 100 通过。

尝试 cmpxchgWeak(99, 100, ...)。

就在线程A尝试 cmpxchg 的瞬间，CPU切换到了 线程B。

线程B 进入循环：

load 得到 current 是 99。

检查 99 < 100 通过。

尝试 cmpxchgWeak(99, 100, ...)。假设 线程B 先成功了。

active_connections 的值现在原子性地变成了 100。

线程B的 tryAcquire 返回 true。

CPU切换回 线程A，继续执行它的 cmpxchgWeak(99, 100, ...)。

CPU现在进行比较：“嘿，active_connections 的值还是 99 吗？”

答案是：“不是！它现在是 100 了！”

于是，cmpxchgWeak 失败，不执行任何修改。

线程A 的 if 判断失败，它不会返回 true。它会回到 while 循环的顶部，开始新一轮的尝试。

线程A 的第二轮循环：

load 得到 current 是 100。

检查 100 >= 100，条件成立。

if 语句执行，函数返回 false。

最终结果： 一个线程成功地将计数器加到了 100，另一个线程安全地失败了。连接数从未超过 100。逻辑完美无缺。

总结

cmpxchg（Compare-and-Swap，比较并交换）是实现所谓的**“无锁（Lock-Free）”**算法的基石。这个循环模式被称为 CAS Loop。

当你的逻辑是简单的**“无条件修改”**（比如 release 时无条件减1），那么 fetchAdd / fetchSub 是最佳选择，因为它更简单、意图更明确。

当你需要**“有条件的修改”**（比如 tryAcquire 时，只有在未满的情况下才加1），fetchAdd 就无能为力了，因为你无法把你的“条件”塞进这个原子操作里。这时，CAS Loop 就是标准的、最高效的解决方案。它允许你在普通代码中进行任意复杂的逻辑判断，然后通过一次原子的 cmpxchg 操作来提交你的修改，同时确保在此期间共享状态没有被其他人改变。
