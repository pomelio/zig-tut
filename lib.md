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
