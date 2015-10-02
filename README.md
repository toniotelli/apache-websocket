# apache-websocket

The apache-websocket module is an Apache 2.x server module that may be used to
process requests using the WebSocket protocol (RFC 6455) by an Apache 2.x
server. The module consists of a plugin architecture for handling WebSocket
messaging. Doing so does _not_ require any knowledge of internal Apache
structures.

This implementation supports protocol versions 7, 8, and 13.

## Download

    $ git clone git://github.com/jchampio/apache-websocket.git

## Building and Installation

SCons may be used to build the module.

    $ scons
    $ sudo scons install

For Windows, do not include the word `sudo` when installing the module. Also,
the `SConstruct` file is hard-coded to look for the Apache headers and
libraries in `C:\Program Files\Apache Software Foundation\Apache2.2`. You
will need to install the headers and libraries when installing Apache. The
`Build Headers and Libraries` option is disabled by default, so you will have
to perform a `Custom` installation of Apache. Refer to the Apache document
entitled _Using Apache HTTP Server on Microsoft Windows_ for more information.

Alternatively, you may use `apxs` to build and install the module. Under Linux
(at least under Ubuntu), use:

    $ sudo apxs2 -i -a -c mod_websocket.c

You probably only want to use the `-a` option the first time you issue the
command, as it may overwrite your configuration each time you execute it (see
below).

You may use `apxs` under Mac OS X if you do not want to use SCons. In that
case, use:

    $ sudo apxs -i -a -c mod_websocket.c

## Plugins

While the module is used to handle the WebSocket protocol, plugins are used to
implement the application-specific handling of WebSocket messages.

A plugin need only have one function exported that returns a pointer to an
initialized `WebSocketPlugin` structure. The `WebSocketPlugin` structure
consists of the structure size, structure version, and several function
pointers. The size should be set to the `sizeof` the `WebSocketPlugin`
structure, the version should be set to 0, and the function pointers should be
set to point to the various functions that will service the requests. The only
required function is the `on_message` function for handling incoming messages.

See `examples/mod_websocket_echo.c` for a simple example implementation of an
"echo" plugin. A sample `client.html` is included as well. If you try it and
you get a message that says Connection Closed, you are likely using a client
that does not support these versions of the protocol.

A more extensive example may be found in
`examples/mod_websocket_dumb_increment.c`. That plugin implements the
dumb-increment-protocol (see libwebsockets by Andy Green for more information
on the protocol). There is a test client for testing the module in
`increment.html`. It uses the WebSocket client API which supports passing
supported protocols in the WebSocket constructor. If your browser does not
support this, either upgrade your browser or modify the plugin so that it
doesn't verify the protocol.

If you provide an `on_connect` function, return a non-null value to accept the
connection, and null if you wish to decline the connection. The return value
will be passed to your other methods for that connection. During your
`on_connect` function, you may access the Apache `request_rec` structure if you
wish. You will have to include the appropriate Apache include files. If you do
not wish to do that, you may also access the headers (both input and output)
using the provided functions. There are also protocol-specific handling
functions for selecting the desired protocol for the WebSocket session. You may
only safely access the `send` or `close` functions in your `on_connect`
function from a separate thread, as the connection will not be completed until
you return from the function.

You may use `apxs`, SCons, or some other build system to be build and install
the plugins. Also, it does not need to be placed in the same directory as the
WebSocket module.

## Configuration

The `http.conf` file is used to configure WebSocket plugins to handle requests
for particular locations. Inside each `Location` block, set the handler, using
the `SetHandler` keyword, to `websocket-handler`. Next, add a
`WebSocketHandler` entry that contains two parameters. The first is the name of
the dynamic plugin library that will service the requests for the specified
location, and the second is the name of the function in the dynamic library
that will initialize the plugin.

Here is an example of the configuration changes to `http.conf` that are used to
handle the WebSocket plugin requests directed at `/echo` under Mac OS X. The
server will initialize the module by calling the `echo_init` function in
`mod_websocket_echo.so`:

    LoadModule websocket_module   libexec/apache2/mod_websocket.so

    <IfModule mod_websocket.c>
      <Location /echo>
        SetHandler websocket-handler
        WebSocketHandler libexec/apache2/mod_websocket_echo.so echo_init
      </Location>
      <Location /dumb-increment>
        SetHandler websocket-handler
        WebSocketHandler libexec/apache2/mod_websocket_dumb_increment.so dumb_increment_init
      </Location>
    </IfModule>

Since we are dealing with messages, not streams, we need to specify a maximum
message size. The default size is 32 megabytes. You may override this value by
specifying a `MaxMessageSize` configuration setting. Here is an example of how
to set the maximum message size is set to 64 megabytes:

    <IfModule mod_websocket.c>
      <Location /echo>
        SetHandler websocket-handler
        WebSocketHandler /usr/lib/apache2/modules/mod_websocket_echo.so echo_init
        MaxMessageSize 67108864
      </Location>
    </IfModule>

Under Linux, the module-specific configuration may be contained in a single
file called `/etc/apache2/mods-available/websocket.load` (your version of Linux
may vary). If you did not use `apxs2` with the `-a` option to initially
create the module, you will have to make a link between
`/etc/apache2/mods-enabled/websocket.load` and
`/etc/apache2/mods-available/websocket.load`. Take a look at the already enabled
modules to see how it should look. Since the directory containing the module is
different from Mac OS X, the configuration will look more like this:

    LoadModule websocket_module   /usr/lib/apache2/modules/mod_websocket.so

    <IfModule mod_websocket.c>
      <Location /echo>
        SetHandler websocket-handler
        WebSocketHandler /usr/lib/apache2/modules/mod_websocket_echo.so echo_init
      </Location>
    </IfModule>

This is the configuration that may be overwritten when the `-a` option is
included using `axps2`, so be careful.

Under Windows, the initialization function is of the form `_echo_init@0`, as it
is using the `__stdcall` calling convention:

    LoadModule websocket_module   modules/mod_websocket.so

    <IfModule mod_websocket.c>
      <Location /echo>
        SetHandler websocket-handler
        WebSocketHandler modules/mod_websocket_echo.so _echo_init@0
      </Location>
    </IfModule>

## Authors

* The original code was written by `self.disconnect`.

## License

Please see the file called LICENSE.
