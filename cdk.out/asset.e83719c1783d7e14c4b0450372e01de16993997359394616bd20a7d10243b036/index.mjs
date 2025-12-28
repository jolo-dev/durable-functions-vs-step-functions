var __defProp = Object.defineProperty;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __esm = (fn, res) => function __init() {
  return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// node_modules/@smithy/protocol-http/dist-es/extensions/httpExtensionConfiguration.js
var getHttpHandlerExtensionConfiguration, resolveHttpHandlerRuntimeConfig;
var init_httpExtensionConfiguration = __esm({
  "node_modules/@smithy/protocol-http/dist-es/extensions/httpExtensionConfiguration.js"() {
    getHttpHandlerExtensionConfiguration = (runtimeConfig) => {
      return {
        setHttpHandler(handler2) {
          runtimeConfig.httpHandler = handler2;
        },
        httpHandler() {
          return runtimeConfig.httpHandler;
        },
        updateHttpClientConfig(key, value) {
          runtimeConfig.httpHandler?.updateHttpClientConfig(key, value);
        },
        httpHandlerConfigs() {
          return runtimeConfig.httpHandler.httpHandlerConfigs();
        }
      };
    };
    resolveHttpHandlerRuntimeConfig = (httpHandlerExtensionConfiguration) => {
      return {
        httpHandler: httpHandlerExtensionConfiguration.httpHandler()
      };
    };
  }
});

// node_modules/@smithy/protocol-http/dist-es/extensions/index.js
var init_extensions = __esm({
  "node_modules/@smithy/protocol-http/dist-es/extensions/index.js"() {
    init_httpExtensionConfiguration();
  }
});

// node_modules/@smithy/types/dist-es/abort.js
var init_abort = __esm({
  "node_modules/@smithy/types/dist-es/abort.js"() {
  }
});

// node_modules/@smithy/types/dist-es/auth/auth.js
var HttpAuthLocation;
var init_auth = __esm({
  "node_modules/@smithy/types/dist-es/auth/auth.js"() {
    (function(HttpAuthLocation2) {
      HttpAuthLocation2["HEADER"] = "header";
      HttpAuthLocation2["QUERY"] = "query";
    })(HttpAuthLocation || (HttpAuthLocation = {}));
  }
});

// node_modules/@smithy/types/dist-es/auth/HttpApiKeyAuth.js
var HttpApiKeyAuthLocation;
var init_HttpApiKeyAuth = __esm({
  "node_modules/@smithy/types/dist-es/auth/HttpApiKeyAuth.js"() {
    (function(HttpApiKeyAuthLocation2) {
      HttpApiKeyAuthLocation2["HEADER"] = "header";
      HttpApiKeyAuthLocation2["QUERY"] = "query";
    })(HttpApiKeyAuthLocation || (HttpApiKeyAuthLocation = {}));
  }
});

// node_modules/@smithy/types/dist-es/auth/HttpAuthScheme.js
var init_HttpAuthScheme = __esm({
  "node_modules/@smithy/types/dist-es/auth/HttpAuthScheme.js"() {
  }
});

// node_modules/@smithy/types/dist-es/auth/HttpAuthSchemeProvider.js
var init_HttpAuthSchemeProvider = __esm({
  "node_modules/@smithy/types/dist-es/auth/HttpAuthSchemeProvider.js"() {
  }
});

// node_modules/@smithy/types/dist-es/auth/HttpSigner.js
var init_HttpSigner = __esm({
  "node_modules/@smithy/types/dist-es/auth/HttpSigner.js"() {
  }
});

// node_modules/@smithy/types/dist-es/auth/IdentityProviderConfig.js
var init_IdentityProviderConfig = __esm({
  "node_modules/@smithy/types/dist-es/auth/IdentityProviderConfig.js"() {
  }
});

// node_modules/@smithy/types/dist-es/auth/index.js
var init_auth2 = __esm({
  "node_modules/@smithy/types/dist-es/auth/index.js"() {
    init_auth();
    init_HttpApiKeyAuth();
    init_HttpAuthScheme();
    init_HttpAuthSchemeProvider();
    init_HttpSigner();
    init_IdentityProviderConfig();
  }
});

// node_modules/@smithy/types/dist-es/blob/blob-payload-input-types.js
var init_blob_payload_input_types = __esm({
  "node_modules/@smithy/types/dist-es/blob/blob-payload-input-types.js"() {
  }
});

// node_modules/@smithy/types/dist-es/checksum.js
var init_checksum = __esm({
  "node_modules/@smithy/types/dist-es/checksum.js"() {
  }
});

// node_modules/@smithy/types/dist-es/client.js
var init_client = __esm({
  "node_modules/@smithy/types/dist-es/client.js"() {
  }
});

// node_modules/@smithy/types/dist-es/command.js
var init_command = __esm({
  "node_modules/@smithy/types/dist-es/command.js"() {
  }
});

// node_modules/@smithy/types/dist-es/connection/config.js
var init_config = __esm({
  "node_modules/@smithy/types/dist-es/connection/config.js"() {
  }
});

// node_modules/@smithy/types/dist-es/connection/manager.js
var init_manager = __esm({
  "node_modules/@smithy/types/dist-es/connection/manager.js"() {
  }
});

// node_modules/@smithy/types/dist-es/connection/pool.js
var init_pool = __esm({
  "node_modules/@smithy/types/dist-es/connection/pool.js"() {
  }
});

// node_modules/@smithy/types/dist-es/connection/index.js
var init_connection = __esm({
  "node_modules/@smithy/types/dist-es/connection/index.js"() {
    init_config();
    init_manager();
    init_pool();
  }
});

// node_modules/@smithy/types/dist-es/crypto.js
var init_crypto = __esm({
  "node_modules/@smithy/types/dist-es/crypto.js"() {
  }
});

// node_modules/@smithy/types/dist-es/encode.js
var init_encode = __esm({
  "node_modules/@smithy/types/dist-es/encode.js"() {
  }
});

// node_modules/@smithy/types/dist-es/endpoint.js
var EndpointURLScheme;
var init_endpoint = __esm({
  "node_modules/@smithy/types/dist-es/endpoint.js"() {
    (function(EndpointURLScheme2) {
      EndpointURLScheme2["HTTP"] = "http";
      EndpointURLScheme2["HTTPS"] = "https";
    })(EndpointURLScheme || (EndpointURLScheme = {}));
  }
});

// node_modules/@smithy/types/dist-es/endpoints/EndpointRuleObject.js
var init_EndpointRuleObject = __esm({
  "node_modules/@smithy/types/dist-es/endpoints/EndpointRuleObject.js"() {
  }
});

// node_modules/@smithy/types/dist-es/endpoints/ErrorRuleObject.js
var init_ErrorRuleObject = __esm({
  "node_modules/@smithy/types/dist-es/endpoints/ErrorRuleObject.js"() {
  }
});

// node_modules/@smithy/types/dist-es/endpoints/RuleSetObject.js
var init_RuleSetObject = __esm({
  "node_modules/@smithy/types/dist-es/endpoints/RuleSetObject.js"() {
  }
});

// node_modules/@smithy/types/dist-es/endpoints/shared.js
var init_shared = __esm({
  "node_modules/@smithy/types/dist-es/endpoints/shared.js"() {
  }
});

// node_modules/@smithy/types/dist-es/endpoints/TreeRuleObject.js
var init_TreeRuleObject = __esm({
  "node_modules/@smithy/types/dist-es/endpoints/TreeRuleObject.js"() {
  }
});

// node_modules/@smithy/types/dist-es/endpoints/index.js
var init_endpoints = __esm({
  "node_modules/@smithy/types/dist-es/endpoints/index.js"() {
    init_EndpointRuleObject();
    init_ErrorRuleObject();
    init_RuleSetObject();
    init_shared();
    init_TreeRuleObject();
  }
});

// node_modules/@smithy/types/dist-es/eventStream.js
var init_eventStream = __esm({
  "node_modules/@smithy/types/dist-es/eventStream.js"() {
  }
});

// node_modules/@smithy/types/dist-es/extensions/checksum.js
var AlgorithmId;
var init_checksum2 = __esm({
  "node_modules/@smithy/types/dist-es/extensions/checksum.js"() {
    (function(AlgorithmId2) {
      AlgorithmId2["MD5"] = "md5";
      AlgorithmId2["CRC32"] = "crc32";
      AlgorithmId2["CRC32C"] = "crc32c";
      AlgorithmId2["SHA1"] = "sha1";
      AlgorithmId2["SHA256"] = "sha256";
    })(AlgorithmId || (AlgorithmId = {}));
  }
});

// node_modules/@smithy/types/dist-es/extensions/defaultClientConfiguration.js
var init_defaultClientConfiguration = __esm({
  "node_modules/@smithy/types/dist-es/extensions/defaultClientConfiguration.js"() {
  }
});

// node_modules/@smithy/types/dist-es/extensions/defaultExtensionConfiguration.js
var init_defaultExtensionConfiguration = __esm({
  "node_modules/@smithy/types/dist-es/extensions/defaultExtensionConfiguration.js"() {
  }
});

// node_modules/@smithy/types/dist-es/extensions/index.js
var init_extensions2 = __esm({
  "node_modules/@smithy/types/dist-es/extensions/index.js"() {
    init_defaultClientConfiguration();
    init_defaultExtensionConfiguration();
    init_checksum2();
  }
});

// node_modules/@smithy/types/dist-es/feature-ids.js
var init_feature_ids = __esm({
  "node_modules/@smithy/types/dist-es/feature-ids.js"() {
  }
});

// node_modules/@smithy/types/dist-es/http.js
var FieldPosition;
var init_http = __esm({
  "node_modules/@smithy/types/dist-es/http.js"() {
    (function(FieldPosition2) {
      FieldPosition2[FieldPosition2["HEADER"] = 0] = "HEADER";
      FieldPosition2[FieldPosition2["TRAILER"] = 1] = "TRAILER";
    })(FieldPosition || (FieldPosition = {}));
  }
});

// node_modules/@smithy/types/dist-es/http/httpHandlerInitialization.js
var init_httpHandlerInitialization = __esm({
  "node_modules/@smithy/types/dist-es/http/httpHandlerInitialization.js"() {
  }
});

// node_modules/@smithy/types/dist-es/identity/apiKeyIdentity.js
var init_apiKeyIdentity = __esm({
  "node_modules/@smithy/types/dist-es/identity/apiKeyIdentity.js"() {
  }
});

// node_modules/@smithy/types/dist-es/identity/awsCredentialIdentity.js
var init_awsCredentialIdentity = __esm({
  "node_modules/@smithy/types/dist-es/identity/awsCredentialIdentity.js"() {
  }
});

// node_modules/@smithy/types/dist-es/identity/identity.js
var init_identity = __esm({
  "node_modules/@smithy/types/dist-es/identity/identity.js"() {
  }
});

// node_modules/@smithy/types/dist-es/identity/tokenIdentity.js
var init_tokenIdentity = __esm({
  "node_modules/@smithy/types/dist-es/identity/tokenIdentity.js"() {
  }
});

// node_modules/@smithy/types/dist-es/identity/index.js
var init_identity2 = __esm({
  "node_modules/@smithy/types/dist-es/identity/index.js"() {
    init_apiKeyIdentity();
    init_awsCredentialIdentity();
    init_identity();
    init_tokenIdentity();
  }
});

// node_modules/@smithy/types/dist-es/logger.js
var init_logger = __esm({
  "node_modules/@smithy/types/dist-es/logger.js"() {
  }
});

// node_modules/@smithy/types/dist-es/middleware.js
var SMITHY_CONTEXT_KEY;
var init_middleware = __esm({
  "node_modules/@smithy/types/dist-es/middleware.js"() {
    SMITHY_CONTEXT_KEY = "__smithy_context";
  }
});

// node_modules/@smithy/types/dist-es/pagination.js
var init_pagination = __esm({
  "node_modules/@smithy/types/dist-es/pagination.js"() {
  }
});

// node_modules/@smithy/types/dist-es/profile.js
var IniSectionType;
var init_profile = __esm({
  "node_modules/@smithy/types/dist-es/profile.js"() {
    (function(IniSectionType2) {
      IniSectionType2["PROFILE"] = "profile";
      IniSectionType2["SSO_SESSION"] = "sso-session";
      IniSectionType2["SERVICES"] = "services";
    })(IniSectionType || (IniSectionType = {}));
  }
});

// node_modules/@smithy/types/dist-es/response.js
var init_response = __esm({
  "node_modules/@smithy/types/dist-es/response.js"() {
  }
});

// node_modules/@smithy/types/dist-es/retry.js
var init_retry = __esm({
  "node_modules/@smithy/types/dist-es/retry.js"() {
  }
});

// node_modules/@smithy/types/dist-es/schema/schema.js
var init_schema = __esm({
  "node_modules/@smithy/types/dist-es/schema/schema.js"() {
  }
});

// node_modules/@smithy/types/dist-es/schema/traits.js
var init_traits = __esm({
  "node_modules/@smithy/types/dist-es/schema/traits.js"() {
  }
});

// node_modules/@smithy/types/dist-es/schema/schema-deprecated.js
var init_schema_deprecated = __esm({
  "node_modules/@smithy/types/dist-es/schema/schema-deprecated.js"() {
  }
});

// node_modules/@smithy/types/dist-es/schema/sentinels.js
var init_sentinels = __esm({
  "node_modules/@smithy/types/dist-es/schema/sentinels.js"() {
  }
});

// node_modules/@smithy/types/dist-es/schema/static-schemas.js
var init_static_schemas = __esm({
  "node_modules/@smithy/types/dist-es/schema/static-schemas.js"() {
  }
});

// node_modules/@smithy/types/dist-es/serde.js
var init_serde = __esm({
  "node_modules/@smithy/types/dist-es/serde.js"() {
  }
});

// node_modules/@smithy/types/dist-es/shapes.js
var init_shapes = __esm({
  "node_modules/@smithy/types/dist-es/shapes.js"() {
  }
});

// node_modules/@smithy/types/dist-es/signature.js
var init_signature = __esm({
  "node_modules/@smithy/types/dist-es/signature.js"() {
  }
});

// node_modules/@smithy/types/dist-es/stream.js
var init_stream = __esm({
  "node_modules/@smithy/types/dist-es/stream.js"() {
  }
});

// node_modules/@smithy/types/dist-es/streaming-payload/streaming-blob-common-types.js
var init_streaming_blob_common_types = __esm({
  "node_modules/@smithy/types/dist-es/streaming-payload/streaming-blob-common-types.js"() {
  }
});

// node_modules/@smithy/types/dist-es/streaming-payload/streaming-blob-payload-input-types.js
var init_streaming_blob_payload_input_types = __esm({
  "node_modules/@smithy/types/dist-es/streaming-payload/streaming-blob-payload-input-types.js"() {
  }
});

// node_modules/@smithy/types/dist-es/streaming-payload/streaming-blob-payload-output-types.js
var init_streaming_blob_payload_output_types = __esm({
  "node_modules/@smithy/types/dist-es/streaming-payload/streaming-blob-payload-output-types.js"() {
  }
});

// node_modules/@smithy/types/dist-es/transfer.js
var RequestHandlerProtocol;
var init_transfer = __esm({
  "node_modules/@smithy/types/dist-es/transfer.js"() {
    (function(RequestHandlerProtocol2) {
      RequestHandlerProtocol2["HTTP_0_9"] = "http/0.9";
      RequestHandlerProtocol2["HTTP_1_0"] = "http/1.0";
      RequestHandlerProtocol2["TDS_8_0"] = "tds/8.0";
    })(RequestHandlerProtocol || (RequestHandlerProtocol = {}));
  }
});

// node_modules/@smithy/types/dist-es/transform/client-payload-blob-type-narrow.js
var init_client_payload_blob_type_narrow = __esm({
  "node_modules/@smithy/types/dist-es/transform/client-payload-blob-type-narrow.js"() {
  }
});

// node_modules/@smithy/types/dist-es/transform/mutable.js
var init_mutable = __esm({
  "node_modules/@smithy/types/dist-es/transform/mutable.js"() {
  }
});

// node_modules/@smithy/types/dist-es/transform/no-undefined.js
var init_no_undefined = __esm({
  "node_modules/@smithy/types/dist-es/transform/no-undefined.js"() {
  }
});

// node_modules/@smithy/types/dist-es/transform/type-transform.js
var init_type_transform = __esm({
  "node_modules/@smithy/types/dist-es/transform/type-transform.js"() {
  }
});

// node_modules/@smithy/types/dist-es/uri.js
var init_uri = __esm({
  "node_modules/@smithy/types/dist-es/uri.js"() {
  }
});

// node_modules/@smithy/types/dist-es/util.js
var init_util = __esm({
  "node_modules/@smithy/types/dist-es/util.js"() {
  }
});

// node_modules/@smithy/types/dist-es/waiter.js
var init_waiter = __esm({
  "node_modules/@smithy/types/dist-es/waiter.js"() {
  }
});

// node_modules/@smithy/types/dist-es/index.js
var init_dist_es = __esm({
  "node_modules/@smithy/types/dist-es/index.js"() {
    init_abort();
    init_auth2();
    init_blob_payload_input_types();
    init_checksum();
    init_client();
    init_command();
    init_connection();
    init_crypto();
    init_encode();
    init_endpoint();
    init_endpoints();
    init_eventStream();
    init_extensions2();
    init_feature_ids();
    init_http();
    init_httpHandlerInitialization();
    init_identity2();
    init_logger();
    init_middleware();
    init_pagination();
    init_profile();
    init_response();
    init_retry();
    init_schema();
    init_traits();
    init_schema_deprecated();
    init_sentinels();
    init_static_schemas();
    init_serde();
    init_shapes();
    init_signature();
    init_stream();
    init_streaming_blob_common_types();
    init_streaming_blob_payload_input_types();
    init_streaming_blob_payload_output_types();
    init_transfer();
    init_client_payload_blob_type_narrow();
    init_mutable();
    init_no_undefined();
    init_type_transform();
    init_uri();
    init_util();
    init_waiter();
  }
});

// node_modules/@smithy/protocol-http/dist-es/Field.js
var init_Field = __esm({
  "node_modules/@smithy/protocol-http/dist-es/Field.js"() {
  }
});

// node_modules/@smithy/protocol-http/dist-es/Fields.js
var init_Fields = __esm({
  "node_modules/@smithy/protocol-http/dist-es/Fields.js"() {
  }
});

// node_modules/@smithy/protocol-http/dist-es/httpHandler.js
var init_httpHandler = __esm({
  "node_modules/@smithy/protocol-http/dist-es/httpHandler.js"() {
  }
});

// node_modules/@smithy/protocol-http/dist-es/httpRequest.js
function cloneQuery(query) {
  return Object.keys(query).reduce((carry, paramName) => {
    const param = query[paramName];
    return {
      ...carry,
      [paramName]: Array.isArray(param) ? [...param] : param
    };
  }, {});
}
var HttpRequest;
var init_httpRequest = __esm({
  "node_modules/@smithy/protocol-http/dist-es/httpRequest.js"() {
    HttpRequest = class _HttpRequest {
      method;
      protocol;
      hostname;
      port;
      path;
      query;
      headers;
      username;
      password;
      fragment;
      body;
      constructor(options) {
        this.method = options.method || "GET";
        this.hostname = options.hostname || "localhost";
        this.port = options.port;
        this.query = options.query || {};
        this.headers = options.headers || {};
        this.body = options.body;
        this.protocol = options.protocol ? options.protocol.slice(-1) !== ":" ? `${options.protocol}:` : options.protocol : "https:";
        this.path = options.path ? options.path.charAt(0) !== "/" ? `/${options.path}` : options.path : "/";
        this.username = options.username;
        this.password = options.password;
        this.fragment = options.fragment;
      }
      static clone(request2) {
        const cloned = new _HttpRequest({
          ...request2,
          headers: { ...request2.headers }
        });
        if (cloned.query) {
          cloned.query = cloneQuery(cloned.query);
        }
        return cloned;
      }
      static isInstance(request2) {
        if (!request2) {
          return false;
        }
        const req = request2;
        return "method" in req && "protocol" in req && "hostname" in req && "path" in req && typeof req["query"] === "object" && typeof req["headers"] === "object";
      }
      clone() {
        return _HttpRequest.clone(this);
      }
    };
  }
});

// node_modules/@smithy/protocol-http/dist-es/httpResponse.js
var HttpResponse;
var init_httpResponse = __esm({
  "node_modules/@smithy/protocol-http/dist-es/httpResponse.js"() {
    HttpResponse = class {
      statusCode;
      reason;
      headers;
      body;
      constructor(options) {
        this.statusCode = options.statusCode;
        this.reason = options.reason;
        this.headers = options.headers || {};
        this.body = options.body;
      }
      static isInstance(response) {
        if (!response)
          return false;
        const resp = response;
        return typeof resp.statusCode === "number" && typeof resp.headers === "object";
      }
    };
  }
});

// node_modules/@smithy/protocol-http/dist-es/isValidHostname.js
var init_isValidHostname = __esm({
  "node_modules/@smithy/protocol-http/dist-es/isValidHostname.js"() {
  }
});

// node_modules/@smithy/protocol-http/dist-es/types.js
var init_types = __esm({
  "node_modules/@smithy/protocol-http/dist-es/types.js"() {
  }
});

// node_modules/@smithy/protocol-http/dist-es/index.js
var init_dist_es2 = __esm({
  "node_modules/@smithy/protocol-http/dist-es/index.js"() {
    init_extensions();
    init_Field();
    init_Fields();
    init_httpHandler();
    init_httpRequest();
    init_httpResponse();
    init_isValidHostname();
    init_types();
  }
});

// node_modules/@aws-sdk/middleware-host-header/dist-es/index.js
function resolveHostHeaderConfig(input) {
  return input;
}
var hostHeaderMiddleware, hostHeaderMiddlewareOptions, getHostHeaderPlugin;
var init_dist_es3 = __esm({
  "node_modules/@aws-sdk/middleware-host-header/dist-es/index.js"() {
    init_dist_es2();
    hostHeaderMiddleware = (options) => (next) => async (args) => {
      if (!HttpRequest.isInstance(args.request))
        return next(args);
      const { request: request2 } = args;
      const { handlerProtocol = "" } = options.requestHandler.metadata || {};
      if (handlerProtocol.indexOf("h2") >= 0 && !request2.headers[":authority"]) {
        delete request2.headers["host"];
        request2.headers[":authority"] = request2.hostname + (request2.port ? ":" + request2.port : "");
      } else if (!request2.headers["host"]) {
        let host = request2.hostname;
        if (request2.port != null)
          host += `:${request2.port}`;
        request2.headers["host"] = host;
      }
      return next(args);
    };
    hostHeaderMiddlewareOptions = {
      name: "hostHeaderMiddleware",
      step: "build",
      priority: "low",
      tags: ["HOST"],
      override: true
    };
    getHostHeaderPlugin = (options) => ({
      applyToStack: (clientStack) => {
        clientStack.add(hostHeaderMiddleware(options), hostHeaderMiddlewareOptions);
      }
    });
  }
});

// node_modules/@aws-sdk/middleware-logger/dist-es/loggerMiddleware.js
var loggerMiddleware, loggerMiddlewareOptions, getLoggerPlugin;
var init_loggerMiddleware = __esm({
  "node_modules/@aws-sdk/middleware-logger/dist-es/loggerMiddleware.js"() {
    loggerMiddleware = () => (next, context) => async (args) => {
      try {
        const response = await next(args);
        const { clientName, commandName, logger: logger2, dynamoDbDocumentClientOptions = {} } = context;
        const { overrideInputFilterSensitiveLog, overrideOutputFilterSensitiveLog } = dynamoDbDocumentClientOptions;
        const inputFilterSensitiveLog = overrideInputFilterSensitiveLog ?? context.inputFilterSensitiveLog;
        const outputFilterSensitiveLog = overrideOutputFilterSensitiveLog ?? context.outputFilterSensitiveLog;
        const { $metadata, ...outputWithoutMetadata } = response.output;
        logger2?.info?.({
          clientName,
          commandName,
          input: inputFilterSensitiveLog(args.input),
          output: outputFilterSensitiveLog(outputWithoutMetadata),
          metadata: $metadata
        });
        return response;
      } catch (error) {
        const { clientName, commandName, logger: logger2, dynamoDbDocumentClientOptions = {} } = context;
        const { overrideInputFilterSensitiveLog } = dynamoDbDocumentClientOptions;
        const inputFilterSensitiveLog = overrideInputFilterSensitiveLog ?? context.inputFilterSensitiveLog;
        logger2?.error?.({
          clientName,
          commandName,
          input: inputFilterSensitiveLog(args.input),
          error,
          metadata: error.$metadata
        });
        throw error;
      }
    };
    loggerMiddlewareOptions = {
      name: "loggerMiddleware",
      tags: ["LOGGER"],
      step: "initialize",
      override: true
    };
    getLoggerPlugin = (options) => ({
      applyToStack: (clientStack) => {
        clientStack.add(loggerMiddleware(), loggerMiddlewareOptions);
      }
    });
  }
});

// node_modules/@aws-sdk/middleware-logger/dist-es/index.js
var init_dist_es4 = __esm({
  "node_modules/@aws-sdk/middleware-logger/dist-es/index.js"() {
    init_loggerMiddleware();
  }
});

// node_modules/@aws-sdk/middleware-recursion-detection/dist-es/configuration.js
var recursionDetectionMiddlewareOptions;
var init_configuration = __esm({
  "node_modules/@aws-sdk/middleware-recursion-detection/dist-es/configuration.js"() {
    recursionDetectionMiddlewareOptions = {
      step: "build",
      tags: ["RECURSION_DETECTION"],
      name: "recursionDetectionMiddleware",
      override: true,
      priority: "low"
    };
  }
});

// node_modules/@aws/lambda-invoke-store/dist-es/invoke-store.js
var PROTECTED_KEYS, NO_GLOBAL_AWS_LAMBDA, InvokeStoreBase, InvokeStoreSingle, InvokeStoreMulti, InvokeStore;
var init_invoke_store = __esm({
  "node_modules/@aws/lambda-invoke-store/dist-es/invoke-store.js"() {
    PROTECTED_KEYS = {
      REQUEST_ID: /* @__PURE__ */ Symbol.for("_AWS_LAMBDA_REQUEST_ID"),
      X_RAY_TRACE_ID: /* @__PURE__ */ Symbol.for("_AWS_LAMBDA_X_RAY_TRACE_ID"),
      TENANT_ID: /* @__PURE__ */ Symbol.for("_AWS_LAMBDA_TENANT_ID")
    };
    NO_GLOBAL_AWS_LAMBDA = ["true", "1"].includes(process.env?.AWS_LAMBDA_NODEJS_NO_GLOBAL_AWSLAMBDA ?? "");
    if (!NO_GLOBAL_AWS_LAMBDA) {
      globalThis.awslambda = globalThis.awslambda || {};
    }
    InvokeStoreBase = class {
      static PROTECTED_KEYS = PROTECTED_KEYS;
      isProtectedKey(key) {
        return Object.values(PROTECTED_KEYS).includes(key);
      }
      getRequestId() {
        return this.get(PROTECTED_KEYS.REQUEST_ID) ?? "-";
      }
      getXRayTraceId() {
        return this.get(PROTECTED_KEYS.X_RAY_TRACE_ID);
      }
      getTenantId() {
        return this.get(PROTECTED_KEYS.TENANT_ID);
      }
    };
    InvokeStoreSingle = class extends InvokeStoreBase {
      currentContext;
      getContext() {
        return this.currentContext;
      }
      hasContext() {
        return this.currentContext !== void 0;
      }
      get(key) {
        return this.currentContext?.[key];
      }
      set(key, value) {
        if (this.isProtectedKey(key)) {
          throw new Error(`Cannot modify protected Lambda context field: ${String(key)}`);
        }
        this.currentContext = this.currentContext || {};
        this.currentContext[key] = value;
      }
      run(context, fn) {
        this.currentContext = context;
        return fn();
      }
    };
    InvokeStoreMulti = class _InvokeStoreMulti extends InvokeStoreBase {
      als;
      static async create() {
        const instance = new _InvokeStoreMulti();
        const asyncHooks = await import("node:async_hooks");
        instance.als = new asyncHooks.AsyncLocalStorage();
        return instance;
      }
      getContext() {
        return this.als.getStore();
      }
      hasContext() {
        return this.als.getStore() !== void 0;
      }
      get(key) {
        return this.als.getStore()?.[key];
      }
      set(key, value) {
        if (this.isProtectedKey(key)) {
          throw new Error(`Cannot modify protected Lambda context field: ${String(key)}`);
        }
        const store = this.als.getStore();
        if (!store) {
          throw new Error("No context available");
        }
        store[key] = value;
      }
      run(context, fn) {
        return this.als.run(context, fn);
      }
    };
    (function(InvokeStore2) {
      let instance = null;
      async function getInstanceAsync() {
        if (!instance) {
          instance = (async () => {
            const isMulti = "AWS_LAMBDA_MAX_CONCURRENCY" in process.env;
            const newInstance = isMulti ? await InvokeStoreMulti.create() : new InvokeStoreSingle();
            if (!NO_GLOBAL_AWS_LAMBDA && globalThis.awslambda?.InvokeStore) {
              return globalThis.awslambda.InvokeStore;
            } else if (!NO_GLOBAL_AWS_LAMBDA && globalThis.awslambda) {
              globalThis.awslambda.InvokeStore = newInstance;
              return newInstance;
            } else {
              return newInstance;
            }
          })();
        }
        return instance;
      }
      InvokeStore2.getInstanceAsync = getInstanceAsync;
      InvokeStore2._testing = process.env.AWS_LAMBDA_BENCHMARK_MODE === "1" ? {
        reset: () => {
          instance = null;
          if (globalThis.awslambda?.InvokeStore) {
            delete globalThis.awslambda.InvokeStore;
          }
          globalThis.awslambda = {};
        }
      } : void 0;
    })(InvokeStore || (InvokeStore = {}));
  }
});

// node_modules/@aws-sdk/middleware-recursion-detection/dist-es/recursionDetectionMiddleware.js
var TRACE_ID_HEADER_NAME, ENV_LAMBDA_FUNCTION_NAME, ENV_TRACE_ID, recursionDetectionMiddleware;
var init_recursionDetectionMiddleware = __esm({
  "node_modules/@aws-sdk/middleware-recursion-detection/dist-es/recursionDetectionMiddleware.js"() {
    init_invoke_store();
    init_dist_es2();
    TRACE_ID_HEADER_NAME = "X-Amzn-Trace-Id";
    ENV_LAMBDA_FUNCTION_NAME = "AWS_LAMBDA_FUNCTION_NAME";
    ENV_TRACE_ID = "_X_AMZN_TRACE_ID";
    recursionDetectionMiddleware = () => (next) => async (args) => {
      const { request: request2 } = args;
      if (!HttpRequest.isInstance(request2)) {
        return next(args);
      }
      const traceIdHeader = Object.keys(request2.headers ?? {}).find((h6) => h6.toLowerCase() === TRACE_ID_HEADER_NAME.toLowerCase()) ?? TRACE_ID_HEADER_NAME;
      if (request2.headers.hasOwnProperty(traceIdHeader)) {
        return next(args);
      }
      const functionName = process.env[ENV_LAMBDA_FUNCTION_NAME];
      const traceIdFromEnv = process.env[ENV_TRACE_ID];
      const invokeStore = await InvokeStore.getInstanceAsync();
      const traceIdFromInvokeStore = invokeStore?.getXRayTraceId();
      const traceId = traceIdFromInvokeStore ?? traceIdFromEnv;
      const nonEmptyString = (str) => typeof str === "string" && str.length > 0;
      if (nonEmptyString(functionName) && nonEmptyString(traceId)) {
        request2.headers[TRACE_ID_HEADER_NAME] = traceId;
      }
      return next({
        ...args,
        request: request2
      });
    };
  }
});

// node_modules/@aws-sdk/middleware-recursion-detection/dist-es/getRecursionDetectionPlugin.js
var getRecursionDetectionPlugin;
var init_getRecursionDetectionPlugin = __esm({
  "node_modules/@aws-sdk/middleware-recursion-detection/dist-es/getRecursionDetectionPlugin.js"() {
    init_configuration();
    init_recursionDetectionMiddleware();
    getRecursionDetectionPlugin = (options) => ({
      applyToStack: (clientStack) => {
        clientStack.add(recursionDetectionMiddleware(), recursionDetectionMiddlewareOptions);
      }
    });
  }
});

// node_modules/@aws-sdk/middleware-recursion-detection/dist-es/index.js
var init_dist_es5 = __esm({
  "node_modules/@aws-sdk/middleware-recursion-detection/dist-es/index.js"() {
    init_getRecursionDetectionPlugin();
    init_recursionDetectionMiddleware();
  }
});

// node_modules/@smithy/core/dist-es/getSmithyContext.js
var init_getSmithyContext = __esm({
  "node_modules/@smithy/core/dist-es/getSmithyContext.js"() {
  }
});

// node_modules/@smithy/util-middleware/dist-es/getSmithyContext.js
var getSmithyContext;
var init_getSmithyContext2 = __esm({
  "node_modules/@smithy/util-middleware/dist-es/getSmithyContext.js"() {
    init_dist_es();
    getSmithyContext = (context) => context[SMITHY_CONTEXT_KEY] || (context[SMITHY_CONTEXT_KEY] = {});
  }
});

// node_modules/@smithy/util-middleware/dist-es/normalizeProvider.js
var normalizeProvider;
var init_normalizeProvider = __esm({
  "node_modules/@smithy/util-middleware/dist-es/normalizeProvider.js"() {
    normalizeProvider = (input) => {
      if (typeof input === "function")
        return input;
      const promisified = Promise.resolve(input);
      return () => promisified;
    };
  }
});

// node_modules/@smithy/util-middleware/dist-es/index.js
var init_dist_es6 = __esm({
  "node_modules/@smithy/util-middleware/dist-es/index.js"() {
    init_getSmithyContext2();
    init_normalizeProvider();
  }
});

// node_modules/@smithy/core/dist-es/middleware-http-auth-scheme/resolveAuthOptions.js
var resolveAuthOptions;
var init_resolveAuthOptions = __esm({
  "node_modules/@smithy/core/dist-es/middleware-http-auth-scheme/resolveAuthOptions.js"() {
    resolveAuthOptions = (candidateAuthOptions, authSchemePreference) => {
      if (!authSchemePreference || authSchemePreference.length === 0) {
        return candidateAuthOptions;
      }
      const preferredAuthOptions = [];
      for (const preferredSchemeName of authSchemePreference) {
        for (const candidateAuthOption of candidateAuthOptions) {
          const candidateAuthSchemeName = candidateAuthOption.schemeId.split("#")[1];
          if (candidateAuthSchemeName === preferredSchemeName) {
            preferredAuthOptions.push(candidateAuthOption);
          }
        }
      }
      for (const candidateAuthOption of candidateAuthOptions) {
        if (!preferredAuthOptions.find(({ schemeId }) => schemeId === candidateAuthOption.schemeId)) {
          preferredAuthOptions.push(candidateAuthOption);
        }
      }
      return preferredAuthOptions;
    };
  }
});

// node_modules/@smithy/core/dist-es/middleware-http-auth-scheme/httpAuthSchemeMiddleware.js
function convertHttpAuthSchemesToMap(httpAuthSchemes) {
  const map = /* @__PURE__ */ new Map();
  for (const scheme of httpAuthSchemes) {
    map.set(scheme.schemeId, scheme);
  }
  return map;
}
var httpAuthSchemeMiddleware;
var init_httpAuthSchemeMiddleware = __esm({
  "node_modules/@smithy/core/dist-es/middleware-http-auth-scheme/httpAuthSchemeMiddleware.js"() {
    init_dist_es6();
    init_resolveAuthOptions();
    httpAuthSchemeMiddleware = (config, mwOptions) => (next, context) => async (args) => {
      const options = config.httpAuthSchemeProvider(await mwOptions.httpAuthSchemeParametersProvider(config, context, args.input));
      const authSchemePreference = config.authSchemePreference ? await config.authSchemePreference() : [];
      const resolvedOptions = resolveAuthOptions(options, authSchemePreference);
      const authSchemes = convertHttpAuthSchemesToMap(config.httpAuthSchemes);
      const smithyContext = getSmithyContext(context);
      const failureReasons = [];
      for (const option of resolvedOptions) {
        const scheme = authSchemes.get(option.schemeId);
        if (!scheme) {
          failureReasons.push(`HttpAuthScheme \`${option.schemeId}\` was not enabled for this service.`);
          continue;
        }
        const identityProvider = scheme.identityProvider(await mwOptions.identityProviderConfigProvider(config));
        if (!identityProvider) {
          failureReasons.push(`HttpAuthScheme \`${option.schemeId}\` did not have an IdentityProvider configured.`);
          continue;
        }
        const { identityProperties = {}, signingProperties = {} } = option.propertiesExtractor?.(config, context) || {};
        option.identityProperties = Object.assign(option.identityProperties || {}, identityProperties);
        option.signingProperties = Object.assign(option.signingProperties || {}, signingProperties);
        smithyContext.selectedHttpAuthScheme = {
          httpAuthOption: option,
          identity: await identityProvider(option.identityProperties),
          signer: scheme.signer
        };
        break;
      }
      if (!smithyContext.selectedHttpAuthScheme) {
        throw new Error(failureReasons.join("\n"));
      }
      return next(args);
    };
  }
});

// node_modules/@smithy/core/dist-es/middleware-http-auth-scheme/getHttpAuthSchemeEndpointRuleSetPlugin.js
var httpAuthSchemeEndpointRuleSetMiddlewareOptions, getHttpAuthSchemeEndpointRuleSetPlugin;
var init_getHttpAuthSchemeEndpointRuleSetPlugin = __esm({
  "node_modules/@smithy/core/dist-es/middleware-http-auth-scheme/getHttpAuthSchemeEndpointRuleSetPlugin.js"() {
    init_httpAuthSchemeMiddleware();
    httpAuthSchemeEndpointRuleSetMiddlewareOptions = {
      step: "serialize",
      tags: ["HTTP_AUTH_SCHEME"],
      name: "httpAuthSchemeMiddleware",
      override: true,
      relation: "before",
      toMiddleware: "endpointV2Middleware"
    };
    getHttpAuthSchemeEndpointRuleSetPlugin = (config, { httpAuthSchemeParametersProvider, identityProviderConfigProvider }) => ({
      applyToStack: (clientStack) => {
        clientStack.addRelativeTo(httpAuthSchemeMiddleware(config, {
          httpAuthSchemeParametersProvider,
          identityProviderConfigProvider
        }), httpAuthSchemeEndpointRuleSetMiddlewareOptions);
      }
    });
  }
});

// node_modules/@smithy/middleware-serde/dist-es/deserializerMiddleware.js
var init_deserializerMiddleware = __esm({
  "node_modules/@smithy/middleware-serde/dist-es/deserializerMiddleware.js"() {
  }
});

// node_modules/@smithy/middleware-serde/dist-es/serializerMiddleware.js
var init_serializerMiddleware = __esm({
  "node_modules/@smithy/middleware-serde/dist-es/serializerMiddleware.js"() {
  }
});

// node_modules/@smithy/middleware-serde/dist-es/serdePlugin.js
var serializerMiddlewareOption;
var init_serdePlugin = __esm({
  "node_modules/@smithy/middleware-serde/dist-es/serdePlugin.js"() {
    serializerMiddlewareOption = {
      name: "serializerMiddleware",
      step: "serialize",
      tags: ["SERIALIZER"],
      override: true
    };
  }
});

// node_modules/@smithy/middleware-serde/dist-es/index.js
var init_dist_es7 = __esm({
  "node_modules/@smithy/middleware-serde/dist-es/index.js"() {
    init_deserializerMiddleware();
    init_serdePlugin();
    init_serializerMiddleware();
  }
});

// node_modules/@smithy/core/dist-es/middleware-http-auth-scheme/getHttpAuthSchemePlugin.js
var httpAuthSchemeMiddlewareOptions;
var init_getHttpAuthSchemePlugin = __esm({
  "node_modules/@smithy/core/dist-es/middleware-http-auth-scheme/getHttpAuthSchemePlugin.js"() {
    init_dist_es7();
    httpAuthSchemeMiddlewareOptions = {
      step: "serialize",
      tags: ["HTTP_AUTH_SCHEME"],
      name: "httpAuthSchemeMiddleware",
      override: true,
      relation: "before",
      toMiddleware: serializerMiddlewareOption.name
    };
  }
});

// node_modules/@smithy/core/dist-es/middleware-http-auth-scheme/index.js
var init_middleware_http_auth_scheme = __esm({
  "node_modules/@smithy/core/dist-es/middleware-http-auth-scheme/index.js"() {
    init_httpAuthSchemeMiddleware();
    init_getHttpAuthSchemeEndpointRuleSetPlugin();
    init_getHttpAuthSchemePlugin();
  }
});

// node_modules/@smithy/core/dist-es/middleware-http-signing/httpSigningMiddleware.js
var defaultErrorHandler, defaultSuccessHandler, httpSigningMiddleware;
var init_httpSigningMiddleware = __esm({
  "node_modules/@smithy/core/dist-es/middleware-http-signing/httpSigningMiddleware.js"() {
    init_dist_es2();
    init_dist_es6();
    defaultErrorHandler = (signingProperties) => (error) => {
      throw error;
    };
    defaultSuccessHandler = (httpResponse, signingProperties) => {
    };
    httpSigningMiddleware = (config) => (next, context) => async (args) => {
      if (!HttpRequest.isInstance(args.request)) {
        return next(args);
      }
      const smithyContext = getSmithyContext(context);
      const scheme = smithyContext.selectedHttpAuthScheme;
      if (!scheme) {
        throw new Error(`No HttpAuthScheme was selected: unable to sign request`);
      }
      const { httpAuthOption: { signingProperties = {} }, identity, signer } = scheme;
      const output = await next({
        ...args,
        request: await signer.sign(args.request, identity, signingProperties)
      }).catch((signer.errorHandler || defaultErrorHandler)(signingProperties));
      (signer.successHandler || defaultSuccessHandler)(output.response, signingProperties);
      return output;
    };
  }
});

// node_modules/@smithy/core/dist-es/middleware-http-signing/getHttpSigningMiddleware.js
var httpSigningMiddlewareOptions, getHttpSigningPlugin;
var init_getHttpSigningMiddleware = __esm({
  "node_modules/@smithy/core/dist-es/middleware-http-signing/getHttpSigningMiddleware.js"() {
    init_httpSigningMiddleware();
    httpSigningMiddlewareOptions = {
      step: "finalizeRequest",
      tags: ["HTTP_SIGNING"],
      name: "httpSigningMiddleware",
      aliases: ["apiKeyMiddleware", "tokenMiddleware", "awsAuthMiddleware"],
      override: true,
      relation: "after",
      toMiddleware: "retryMiddleware"
    };
    getHttpSigningPlugin = (config) => ({
      applyToStack: (clientStack) => {
        clientStack.addRelativeTo(httpSigningMiddleware(config), httpSigningMiddlewareOptions);
      }
    });
  }
});

// node_modules/@smithy/core/dist-es/middleware-http-signing/index.js
var init_middleware_http_signing = __esm({
  "node_modules/@smithy/core/dist-es/middleware-http-signing/index.js"() {
    init_httpSigningMiddleware();
    init_getHttpSigningMiddleware();
  }
});

// node_modules/@smithy/core/dist-es/normalizeProvider.js
var normalizeProvider2;
var init_normalizeProvider2 = __esm({
  "node_modules/@smithy/core/dist-es/normalizeProvider.js"() {
    normalizeProvider2 = (input) => {
      if (typeof input === "function")
        return input;
      const promisified = Promise.resolve(input);
      return () => promisified;
    };
  }
});

// node_modules/@smithy/core/dist-es/pagination/createPaginator.js
function createPaginator(ClientCtor, CommandCtor, inputTokenName, outputTokenName, pageSizeTokenName) {
  return async function* paginateOperation(config, input, ...additionalArguments) {
    const _input = input;
    let token = config.startingToken ?? _input[inputTokenName];
    let hasNext = true;
    let page;
    while (hasNext) {
      _input[inputTokenName] = token;
      if (pageSizeTokenName) {
        _input[pageSizeTokenName] = _input[pageSizeTokenName] ?? config.pageSize;
      }
      if (config.client instanceof ClientCtor) {
        page = await makePagedClientRequest(CommandCtor, config.client, input, config.withCommand, ...additionalArguments);
      } else {
        throw new Error(`Invalid client, expected instance of ${ClientCtor.name}`);
      }
      yield page;
      const prevToken = token;
      token = get(page, outputTokenName);
      hasNext = !!(token && (!config.stopOnSameToken || token !== prevToken));
    }
    return void 0;
  };
}
var makePagedClientRequest, get;
var init_createPaginator = __esm({
  "node_modules/@smithy/core/dist-es/pagination/createPaginator.js"() {
    makePagedClientRequest = async (CommandCtor, client, input, withCommand = (_) => _, ...args) => {
      let command = new CommandCtor(input);
      command = withCommand(command) ?? command;
      return await client.send(command, ...args);
    };
    get = (fromObject, path) => {
      let cursor = fromObject;
      const pathComponents = path.split(".");
      for (const step of pathComponents) {
        if (!cursor || typeof cursor !== "object") {
          return void 0;
        }
        cursor = cursor[step];
      }
      return cursor;
    };
  }
});

// node_modules/@smithy/is-array-buffer/dist-es/index.js
var isArrayBuffer;
var init_dist_es8 = __esm({
  "node_modules/@smithy/is-array-buffer/dist-es/index.js"() {
    isArrayBuffer = (arg) => typeof ArrayBuffer === "function" && arg instanceof ArrayBuffer || Object.prototype.toString.call(arg) === "[object ArrayBuffer]";
  }
});

// node_modules/@smithy/util-buffer-from/dist-es/index.js
import { Buffer as Buffer2 } from "buffer";
var fromArrayBuffer, fromString;
var init_dist_es9 = __esm({
  "node_modules/@smithy/util-buffer-from/dist-es/index.js"() {
    init_dist_es8();
    fromArrayBuffer = (input, offset = 0, length = input.byteLength - offset) => {
      if (!isArrayBuffer(input)) {
        throw new TypeError(`The "input" argument must be ArrayBuffer. Received type ${typeof input} (${input})`);
      }
      return Buffer2.from(input, offset, length);
    };
    fromString = (input, encoding) => {
      if (typeof input !== "string") {
        throw new TypeError(`The "input" argument must be of type string. Received type ${typeof input} (${input})`);
      }
      return encoding ? Buffer2.from(input, encoding) : Buffer2.from(input);
    };
  }
});

// node_modules/@smithy/util-base64/dist-es/fromBase64.js
var BASE64_REGEX, fromBase64;
var init_fromBase64 = __esm({
  "node_modules/@smithy/util-base64/dist-es/fromBase64.js"() {
    init_dist_es9();
    BASE64_REGEX = /^[A-Za-z0-9+/]*={0,2}$/;
    fromBase64 = (input) => {
      if (input.length * 3 % 4 !== 0) {
        throw new TypeError(`Incorrect padding on base64 string.`);
      }
      if (!BASE64_REGEX.exec(input)) {
        throw new TypeError(`Invalid base64 string.`);
      }
      const buffer = fromString(input, "base64");
      return new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    };
  }
});

// node_modules/@smithy/util-utf8/dist-es/fromUtf8.js
var fromUtf8;
var init_fromUtf8 = __esm({
  "node_modules/@smithy/util-utf8/dist-es/fromUtf8.js"() {
    init_dist_es9();
    fromUtf8 = (input) => {
      const buf = fromString(input, "utf8");
      return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength / Uint8Array.BYTES_PER_ELEMENT);
    };
  }
});

// node_modules/@smithy/util-utf8/dist-es/toUint8Array.js
var toUint8Array;
var init_toUint8Array = __esm({
  "node_modules/@smithy/util-utf8/dist-es/toUint8Array.js"() {
    init_fromUtf8();
    toUint8Array = (data) => {
      if (typeof data === "string") {
        return fromUtf8(data);
      }
      if (ArrayBuffer.isView(data)) {
        return new Uint8Array(data.buffer, data.byteOffset, data.byteLength / Uint8Array.BYTES_PER_ELEMENT);
      }
      return new Uint8Array(data);
    };
  }
});

// node_modules/@smithy/util-utf8/dist-es/toUtf8.js
var toUtf8;
var init_toUtf8 = __esm({
  "node_modules/@smithy/util-utf8/dist-es/toUtf8.js"() {
    init_dist_es9();
    toUtf8 = (input) => {
      if (typeof input === "string") {
        return input;
      }
      if (typeof input !== "object" || typeof input.byteOffset !== "number" || typeof input.byteLength !== "number") {
        throw new Error("@smithy/util-utf8: toUtf8 encoder function only accepts string | Uint8Array.");
      }
      return fromArrayBuffer(input.buffer, input.byteOffset, input.byteLength).toString("utf8");
    };
  }
});

// node_modules/@smithy/util-utf8/dist-es/index.js
var init_dist_es10 = __esm({
  "node_modules/@smithy/util-utf8/dist-es/index.js"() {
    init_fromUtf8();
    init_toUint8Array();
    init_toUtf8();
  }
});

// node_modules/@smithy/util-base64/dist-es/toBase64.js
var toBase64;
var init_toBase64 = __esm({
  "node_modules/@smithy/util-base64/dist-es/toBase64.js"() {
    init_dist_es9();
    init_dist_es10();
    toBase64 = (_input) => {
      let input;
      if (typeof _input === "string") {
        input = fromUtf8(_input);
      } else {
        input = _input;
      }
      if (typeof input !== "object" || typeof input.byteOffset !== "number" || typeof input.byteLength !== "number") {
        throw new Error("@smithy/util-base64: toBase64 encoder function only accepts string | Uint8Array.");
      }
      return fromArrayBuffer(input.buffer, input.byteOffset, input.byteLength).toString("base64");
    };
  }
});

// node_modules/@smithy/util-base64/dist-es/index.js
var init_dist_es11 = __esm({
  "node_modules/@smithy/util-base64/dist-es/index.js"() {
    init_fromBase64();
    init_toBase64();
  }
});

// node_modules/@smithy/util-stream/dist-es/blob/Uint8ArrayBlobAdapter.js
var Uint8ArrayBlobAdapter;
var init_Uint8ArrayBlobAdapter = __esm({
  "node_modules/@smithy/util-stream/dist-es/blob/Uint8ArrayBlobAdapter.js"() {
    init_dist_es11();
    init_dist_es10();
    Uint8ArrayBlobAdapter = class _Uint8ArrayBlobAdapter extends Uint8Array {
      static fromString(source, encoding = "utf-8") {
        if (typeof source === "string") {
          if (encoding === "base64") {
            return _Uint8ArrayBlobAdapter.mutate(fromBase64(source));
          }
          return _Uint8ArrayBlobAdapter.mutate(fromUtf8(source));
        }
        throw new Error(`Unsupported conversion from ${typeof source} to Uint8ArrayBlobAdapter.`);
      }
      static mutate(source) {
        Object.setPrototypeOf(source, _Uint8ArrayBlobAdapter.prototype);
        return source;
      }
      transformToString(encoding = "utf-8") {
        if (encoding === "base64") {
          return toBase64(this);
        }
        return toUtf8(this);
      }
    };
  }
});

// node_modules/@smithy/util-stream/dist-es/checksum/ChecksumStream.js
var init_ChecksumStream = __esm({
  "node_modules/@smithy/util-stream/dist-es/checksum/ChecksumStream.js"() {
  }
});

// node_modules/@smithy/util-stream/dist-es/stream-type-check.js
var isReadableStream;
var init_stream_type_check = __esm({
  "node_modules/@smithy/util-stream/dist-es/stream-type-check.js"() {
    isReadableStream = (stream) => typeof ReadableStream === "function" && (stream?.constructor?.name === ReadableStream.name || stream instanceof ReadableStream);
  }
});

// node_modules/@smithy/util-stream/dist-es/checksum/createChecksumStream.js
var init_createChecksumStream = __esm({
  "node_modules/@smithy/util-stream/dist-es/checksum/createChecksumStream.js"() {
  }
});

// node_modules/@smithy/util-stream/dist-es/createBufferedReadable.js
var init_createBufferedReadable = __esm({
  "node_modules/@smithy/util-stream/dist-es/createBufferedReadable.js"() {
  }
});

// node_modules/@smithy/util-stream/dist-es/getAwsChunkedEncodingStream.js
var init_getAwsChunkedEncodingStream = __esm({
  "node_modules/@smithy/util-stream/dist-es/getAwsChunkedEncodingStream.js"() {
  }
});

// node_modules/@smithy/util-stream/dist-es/headStream.js
var init_headStream = __esm({
  "node_modules/@smithy/util-stream/dist-es/headStream.js"() {
  }
});

// node_modules/@smithy/util-uri-escape/dist-es/escape-uri.js
var escapeUri, hexEncode;
var init_escape_uri = __esm({
  "node_modules/@smithy/util-uri-escape/dist-es/escape-uri.js"() {
    escapeUri = (uri) => encodeURIComponent(uri).replace(/[!'()*]/g, hexEncode);
    hexEncode = (c6) => `%${c6.charCodeAt(0).toString(16).toUpperCase()}`;
  }
});

// node_modules/@smithy/util-uri-escape/dist-es/escape-uri-path.js
var init_escape_uri_path = __esm({
  "node_modules/@smithy/util-uri-escape/dist-es/escape-uri-path.js"() {
  }
});

// node_modules/@smithy/util-uri-escape/dist-es/index.js
var init_dist_es12 = __esm({
  "node_modules/@smithy/util-uri-escape/dist-es/index.js"() {
    init_escape_uri();
    init_escape_uri_path();
  }
});

// node_modules/@smithy/querystring-builder/dist-es/index.js
function buildQueryString(query) {
  const parts = [];
  for (let key of Object.keys(query).sort()) {
    const value = query[key];
    key = escapeUri(key);
    if (Array.isArray(value)) {
      for (let i6 = 0, iLen = value.length; i6 < iLen; i6++) {
        parts.push(`${key}=${escapeUri(value[i6])}`);
      }
    } else {
      let qsEntry = key;
      if (value || typeof value === "string") {
        qsEntry += `=${escapeUri(value)}`;
      }
      parts.push(qsEntry);
    }
  }
  return parts.join("&");
}
var init_dist_es13 = __esm({
  "node_modules/@smithy/querystring-builder/dist-es/index.js"() {
    init_dist_es12();
  }
});

// node_modules/@smithy/node-http-handler/dist-es/constants.js
var NODEJS_TIMEOUT_ERROR_CODES;
var init_constants = __esm({
  "node_modules/@smithy/node-http-handler/dist-es/constants.js"() {
    NODEJS_TIMEOUT_ERROR_CODES = ["ECONNRESET", "EPIPE", "ETIMEDOUT"];
  }
});

// node_modules/@smithy/node-http-handler/dist-es/get-transformed-headers.js
var getTransformedHeaders;
var init_get_transformed_headers = __esm({
  "node_modules/@smithy/node-http-handler/dist-es/get-transformed-headers.js"() {
    getTransformedHeaders = (headers) => {
      const transformedHeaders = {};
      for (const name of Object.keys(headers)) {
        const headerValues = headers[name];
        transformedHeaders[name] = Array.isArray(headerValues) ? headerValues.join(",") : headerValues;
      }
      return transformedHeaders;
    };
  }
});

// node_modules/@smithy/node-http-handler/dist-es/timing.js
var timing;
var init_timing = __esm({
  "node_modules/@smithy/node-http-handler/dist-es/timing.js"() {
    timing = {
      setTimeout: (cb, ms) => setTimeout(cb, ms),
      clearTimeout: (timeoutId) => clearTimeout(timeoutId)
    };
  }
});

// node_modules/@smithy/node-http-handler/dist-es/set-connection-timeout.js
var DEFER_EVENT_LISTENER_TIME, setConnectionTimeout;
var init_set_connection_timeout = __esm({
  "node_modules/@smithy/node-http-handler/dist-es/set-connection-timeout.js"() {
    init_timing();
    DEFER_EVENT_LISTENER_TIME = 1e3;
    setConnectionTimeout = (request2, reject, timeoutInMs = 0) => {
      if (!timeoutInMs) {
        return -1;
      }
      const registerTimeout = (offset) => {
        const timeoutId = timing.setTimeout(() => {
          request2.destroy();
          reject(Object.assign(new Error(`@smithy/node-http-handler - the request socket did not establish a connection with the server within the configured timeout of ${timeoutInMs} ms.`), {
            name: "TimeoutError"
          }));
        }, timeoutInMs - offset);
        const doWithSocket = (socket) => {
          if (socket?.connecting) {
            socket.on("connect", () => {
              timing.clearTimeout(timeoutId);
            });
          } else {
            timing.clearTimeout(timeoutId);
          }
        };
        if (request2.socket) {
          doWithSocket(request2.socket);
        } else {
          request2.on("socket", doWithSocket);
        }
      };
      if (timeoutInMs < 2e3) {
        registerTimeout(0);
        return 0;
      }
      return timing.setTimeout(registerTimeout.bind(null, DEFER_EVENT_LISTENER_TIME), DEFER_EVENT_LISTENER_TIME);
    };
  }
});

// node_modules/@smithy/node-http-handler/dist-es/set-request-timeout.js
var setRequestTimeout;
var init_set_request_timeout = __esm({
  "node_modules/@smithy/node-http-handler/dist-es/set-request-timeout.js"() {
    init_timing();
    setRequestTimeout = (req, reject, timeoutInMs = 0, throwOnRequestTimeout, logger2) => {
      if (timeoutInMs) {
        return timing.setTimeout(() => {
          let msg = `@smithy/node-http-handler - [${throwOnRequestTimeout ? "ERROR" : "WARN"}] a request has exceeded the configured ${timeoutInMs} ms requestTimeout.`;
          if (throwOnRequestTimeout) {
            const error = Object.assign(new Error(msg), {
              name: "TimeoutError",
              code: "ETIMEDOUT"
            });
            req.destroy(error);
            reject(error);
          } else {
            msg += ` Init client requestHandler with throwOnRequestTimeout=true to turn this into an error.`;
            logger2?.warn?.(msg);
          }
        }, timeoutInMs);
      }
      return -1;
    };
  }
});

// node_modules/@smithy/node-http-handler/dist-es/set-socket-keep-alive.js
var DEFER_EVENT_LISTENER_TIME2, setSocketKeepAlive;
var init_set_socket_keep_alive = __esm({
  "node_modules/@smithy/node-http-handler/dist-es/set-socket-keep-alive.js"() {
    init_timing();
    DEFER_EVENT_LISTENER_TIME2 = 3e3;
    setSocketKeepAlive = (request2, { keepAlive, keepAliveMsecs }, deferTimeMs = DEFER_EVENT_LISTENER_TIME2) => {
      if (keepAlive !== true) {
        return -1;
      }
      const registerListener = () => {
        if (request2.socket) {
          request2.socket.setKeepAlive(keepAlive, keepAliveMsecs || 0);
        } else {
          request2.on("socket", (socket) => {
            socket.setKeepAlive(keepAlive, keepAliveMsecs || 0);
          });
        }
      };
      if (deferTimeMs === 0) {
        registerListener();
        return 0;
      }
      return timing.setTimeout(registerListener, deferTimeMs);
    };
  }
});

// node_modules/@smithy/node-http-handler/dist-es/set-socket-timeout.js
var DEFER_EVENT_LISTENER_TIME3, setSocketTimeout;
var init_set_socket_timeout = __esm({
  "node_modules/@smithy/node-http-handler/dist-es/set-socket-timeout.js"() {
    init_timing();
    DEFER_EVENT_LISTENER_TIME3 = 3e3;
    setSocketTimeout = (request2, reject, timeoutInMs = 0) => {
      const registerTimeout = (offset) => {
        const timeout = timeoutInMs - offset;
        const onTimeout = () => {
          request2.destroy();
          reject(Object.assign(new Error(`@smithy/node-http-handler - the request socket timed out after ${timeoutInMs} ms of inactivity (configured by client requestHandler).`), { name: "TimeoutError" }));
        };
        if (request2.socket) {
          request2.socket.setTimeout(timeout, onTimeout);
          request2.on("close", () => request2.socket?.removeListener("timeout", onTimeout));
        } else {
          request2.setTimeout(timeout, onTimeout);
        }
      };
      if (0 < timeoutInMs && timeoutInMs < 6e3) {
        registerTimeout(0);
        return 0;
      }
      return timing.setTimeout(registerTimeout.bind(null, timeoutInMs === 0 ? 0 : DEFER_EVENT_LISTENER_TIME3), DEFER_EVENT_LISTENER_TIME3);
    };
  }
});

// node_modules/@smithy/node-http-handler/dist-es/write-request-body.js
import { Readable } from "stream";
async function writeRequestBody(httpRequest2, request2, maxContinueTimeoutMs = MIN_WAIT_TIME, externalAgent = false) {
  const headers = request2.headers ?? {};
  const expect = headers.Expect || headers.expect;
  let timeoutId = -1;
  let sendBody = true;
  if (!externalAgent && expect === "100-continue") {
    sendBody = await Promise.race([
      new Promise((resolve) => {
        timeoutId = Number(timing.setTimeout(() => resolve(true), Math.max(MIN_WAIT_TIME, maxContinueTimeoutMs)));
      }),
      new Promise((resolve) => {
        httpRequest2.on("continue", () => {
          timing.clearTimeout(timeoutId);
          resolve(true);
        });
        httpRequest2.on("response", () => {
          timing.clearTimeout(timeoutId);
          resolve(false);
        });
        httpRequest2.on("error", () => {
          timing.clearTimeout(timeoutId);
          resolve(false);
        });
      })
    ]);
  }
  if (sendBody) {
    writeBody(httpRequest2, request2.body);
  }
}
function writeBody(httpRequest2, body) {
  if (body instanceof Readable) {
    body.pipe(httpRequest2);
    return;
  }
  if (body) {
    if (Buffer.isBuffer(body) || typeof body === "string") {
      httpRequest2.end(body);
      return;
    }
    const uint8 = body;
    if (typeof uint8 === "object" && uint8.buffer && typeof uint8.byteOffset === "number" && typeof uint8.byteLength === "number") {
      httpRequest2.end(Buffer.from(uint8.buffer, uint8.byteOffset, uint8.byteLength));
      return;
    }
    httpRequest2.end(Buffer.from(body));
    return;
  }
  httpRequest2.end();
}
var MIN_WAIT_TIME;
var init_write_request_body = __esm({
  "node_modules/@smithy/node-http-handler/dist-es/write-request-body.js"() {
    init_timing();
    MIN_WAIT_TIME = 6e3;
  }
});

// node_modules/@smithy/node-http-handler/dist-es/node-http-handler.js
import { Agent as hAgent, request as hRequest } from "http";
import { Agent as hsAgent, request as hsRequest } from "https";
var NodeHttpHandler;
var init_node_http_handler = __esm({
  "node_modules/@smithy/node-http-handler/dist-es/node-http-handler.js"() {
    init_dist_es2();
    init_dist_es13();
    init_constants();
    init_get_transformed_headers();
    init_set_connection_timeout();
    init_set_request_timeout();
    init_set_socket_keep_alive();
    init_set_socket_timeout();
    init_timing();
    init_write_request_body();
    NodeHttpHandler = class _NodeHttpHandler {
      config;
      configProvider;
      socketWarningTimestamp = 0;
      externalAgent = false;
      metadata = { handlerProtocol: "http/1.1" };
      static create(instanceOrOptions) {
        if (typeof instanceOrOptions?.handle === "function") {
          return instanceOrOptions;
        }
        return new _NodeHttpHandler(instanceOrOptions);
      }
      static checkSocketUsage(agent, socketWarningTimestamp, logger2 = console) {
        const { sockets, requests, maxSockets } = agent;
        if (typeof maxSockets !== "number" || maxSockets === Infinity) {
          return socketWarningTimestamp;
        }
        const interval = 15e3;
        if (Date.now() - interval < socketWarningTimestamp) {
          return socketWarningTimestamp;
        }
        if (sockets && requests) {
          for (const origin in sockets) {
            const socketsInUse = sockets[origin]?.length ?? 0;
            const requestsEnqueued = requests[origin]?.length ?? 0;
            if (socketsInUse >= maxSockets && requestsEnqueued >= 2 * maxSockets) {
              logger2?.warn?.(`@smithy/node-http-handler:WARN - socket usage at capacity=${socketsInUse} and ${requestsEnqueued} additional requests are enqueued.
See https://docs.aws.amazon.com/sdk-for-javascript/v3/developer-guide/node-configuring-maxsockets.html
or increase socketAcquisitionWarningTimeout=(millis) in the NodeHttpHandler config.`);
              return Date.now();
            }
          }
        }
        return socketWarningTimestamp;
      }
      constructor(options) {
        this.configProvider = new Promise((resolve, reject) => {
          if (typeof options === "function") {
            options().then((_options) => {
              resolve(this.resolveDefaultConfig(_options));
            }).catch(reject);
          } else {
            resolve(this.resolveDefaultConfig(options));
          }
        });
      }
      resolveDefaultConfig(options) {
        const { requestTimeout, connectionTimeout, socketTimeout, socketAcquisitionWarningTimeout, httpAgent, httpsAgent, throwOnRequestTimeout } = options || {};
        const keepAlive = true;
        const maxSockets = 50;
        return {
          connectionTimeout,
          requestTimeout,
          socketTimeout,
          socketAcquisitionWarningTimeout,
          throwOnRequestTimeout,
          httpAgent: (() => {
            if (httpAgent instanceof hAgent || typeof httpAgent?.destroy === "function") {
              this.externalAgent = true;
              return httpAgent;
            }
            return new hAgent({ keepAlive, maxSockets, ...httpAgent });
          })(),
          httpsAgent: (() => {
            if (httpsAgent instanceof hsAgent || typeof httpsAgent?.destroy === "function") {
              this.externalAgent = true;
              return httpsAgent;
            }
            return new hsAgent({ keepAlive, maxSockets, ...httpsAgent });
          })(),
          logger: console
        };
      }
      destroy() {
        this.config?.httpAgent?.destroy();
        this.config?.httpsAgent?.destroy();
      }
      async handle(request2, { abortSignal, requestTimeout } = {}) {
        if (!this.config) {
          this.config = await this.configProvider;
        }
        return new Promise((_resolve, _reject) => {
          const config = this.config;
          let writeRequestBodyPromise = void 0;
          const timeouts = [];
          const resolve = async (arg) => {
            await writeRequestBodyPromise;
            timeouts.forEach(timing.clearTimeout);
            _resolve(arg);
          };
          const reject = async (arg) => {
            await writeRequestBodyPromise;
            timeouts.forEach(timing.clearTimeout);
            _reject(arg);
          };
          if (abortSignal?.aborted) {
            const abortError = new Error("Request aborted");
            abortError.name = "AbortError";
            reject(abortError);
            return;
          }
          const isSSL = request2.protocol === "https:";
          const headers = request2.headers ?? {};
          const expectContinue = (headers.Expect ?? headers.expect) === "100-continue";
          let agent = isSSL ? config.httpsAgent : config.httpAgent;
          if (expectContinue && !this.externalAgent) {
            agent = new (isSSL ? hsAgent : hAgent)({
              keepAlive: false,
              maxSockets: Infinity
            });
          }
          timeouts.push(timing.setTimeout(() => {
            this.socketWarningTimestamp = _NodeHttpHandler.checkSocketUsage(agent, this.socketWarningTimestamp, config.logger);
          }, config.socketAcquisitionWarningTimeout ?? (config.requestTimeout ?? 2e3) + (config.connectionTimeout ?? 1e3)));
          const queryString = buildQueryString(request2.query || {});
          let auth = void 0;
          if (request2.username != null || request2.password != null) {
            const username = request2.username ?? "";
            const password = request2.password ?? "";
            auth = `${username}:${password}`;
          }
          let path = request2.path;
          if (queryString) {
            path += `?${queryString}`;
          }
          if (request2.fragment) {
            path += `#${request2.fragment}`;
          }
          let hostname = request2.hostname ?? "";
          if (hostname[0] === "[" && hostname.endsWith("]")) {
            hostname = request2.hostname.slice(1, -1);
          } else {
            hostname = request2.hostname;
          }
          const nodeHttpsOptions = {
            headers: request2.headers,
            host: hostname,
            method: request2.method,
            path,
            port: request2.port,
            agent,
            auth
          };
          const requestFunc = isSSL ? hsRequest : hRequest;
          const req = requestFunc(nodeHttpsOptions, (res) => {
            const httpResponse = new HttpResponse({
              statusCode: res.statusCode || -1,
              reason: res.statusMessage,
              headers: getTransformedHeaders(res.headers),
              body: res
            });
            resolve({ response: httpResponse });
          });
          req.on("error", (err) => {
            if (NODEJS_TIMEOUT_ERROR_CODES.includes(err.code)) {
              reject(Object.assign(err, { name: "TimeoutError" }));
            } else {
              reject(err);
            }
          });
          if (abortSignal) {
            const onAbort = () => {
              req.destroy();
              const abortError = new Error("Request aborted");
              abortError.name = "AbortError";
              reject(abortError);
            };
            if (typeof abortSignal.addEventListener === "function") {
              const signal = abortSignal;
              signal.addEventListener("abort", onAbort, { once: true });
              req.once("close", () => signal.removeEventListener("abort", onAbort));
            } else {
              abortSignal.onabort = onAbort;
            }
          }
          const effectiveRequestTimeout = requestTimeout ?? config.requestTimeout;
          timeouts.push(setConnectionTimeout(req, reject, config.connectionTimeout));
          timeouts.push(setRequestTimeout(req, reject, effectiveRequestTimeout, config.throwOnRequestTimeout, config.logger ?? console));
          timeouts.push(setSocketTimeout(req, reject, config.socketTimeout));
          const httpAgent = nodeHttpsOptions.agent;
          if (typeof httpAgent === "object" && "keepAlive" in httpAgent) {
            timeouts.push(setSocketKeepAlive(req, {
              keepAlive: httpAgent.keepAlive,
              keepAliveMsecs: httpAgent.keepAliveMsecs
            }));
          }
          writeRequestBodyPromise = writeRequestBody(req, request2, effectiveRequestTimeout, this.externalAgent).catch((e6) => {
            timeouts.forEach(timing.clearTimeout);
            return _reject(e6);
          });
        });
      }
      updateHttpClientConfig(key, value) {
        this.config = void 0;
        this.configProvider = this.configProvider.then((config) => {
          return {
            ...config,
            [key]: value
          };
        });
      }
      httpHandlerConfigs() {
        return this.config ?? {};
      }
    };
  }
});

// node_modules/@smithy/node-http-handler/dist-es/node-http2-handler.js
var init_node_http2_handler = __esm({
  "node_modules/@smithy/node-http-handler/dist-es/node-http2-handler.js"() {
  }
});

// node_modules/@smithy/node-http-handler/dist-es/stream-collector/collector.js
import { Writable } from "stream";
var Collector;
var init_collector = __esm({
  "node_modules/@smithy/node-http-handler/dist-es/stream-collector/collector.js"() {
    Collector = class extends Writable {
      bufferedBytes = [];
      _write(chunk, encoding, callback) {
        this.bufferedBytes.push(chunk);
        callback();
      }
    };
  }
});

// node_modules/@smithy/node-http-handler/dist-es/stream-collector/index.js
async function collectReadableStream(stream) {
  const chunks = [];
  const reader = stream.getReader();
  let isDone = false;
  let length = 0;
  while (!isDone) {
    const { done, value } = await reader.read();
    if (value) {
      chunks.push(value);
      length += value.length;
    }
    isDone = done;
  }
  const collected = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    collected.set(chunk, offset);
    offset += chunk.length;
  }
  return collected;
}
var streamCollector, isReadableStreamInstance;
var init_stream_collector = __esm({
  "node_modules/@smithy/node-http-handler/dist-es/stream-collector/index.js"() {
    init_collector();
    streamCollector = (stream) => {
      if (isReadableStreamInstance(stream)) {
        return collectReadableStream(stream);
      }
      return new Promise((resolve, reject) => {
        const collector = new Collector();
        stream.pipe(collector);
        stream.on("error", (err) => {
          collector.end();
          reject(err);
        });
        collector.on("error", reject);
        collector.on("finish", function() {
          const bytes = new Uint8Array(Buffer.concat(this.bufferedBytes));
          resolve(bytes);
        });
      });
    };
    isReadableStreamInstance = (stream) => typeof ReadableStream === "function" && stream instanceof ReadableStream;
  }
});

// node_modules/@smithy/node-http-handler/dist-es/index.js
var init_dist_es14 = __esm({
  "node_modules/@smithy/node-http-handler/dist-es/index.js"() {
    init_node_http_handler();
    init_node_http2_handler();
    init_stream_collector();
  }
});

// node_modules/@smithy/fetch-http-handler/dist-es/fetch-http-handler.js
var init_fetch_http_handler = __esm({
  "node_modules/@smithy/fetch-http-handler/dist-es/fetch-http-handler.js"() {
  }
});

// node_modules/@smithy/fetch-http-handler/dist-es/stream-collector.js
async function collectBlob(blob) {
  const base64 = await readToBase64(blob);
  const arrayBuffer = fromBase64(base64);
  return new Uint8Array(arrayBuffer);
}
async function collectStream(stream) {
  const chunks = [];
  const reader = stream.getReader();
  let isDone = false;
  let length = 0;
  while (!isDone) {
    const { done, value } = await reader.read();
    if (value) {
      chunks.push(value);
      length += value.length;
    }
    isDone = done;
  }
  const collected = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    collected.set(chunk, offset);
    offset += chunk.length;
  }
  return collected;
}
function readToBase64(blob) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onloadend = () => {
      if (reader.readyState !== 2) {
        return reject(new Error("Reader aborted too early"));
      }
      const result = reader.result ?? "";
      const commaIndex = result.indexOf(",");
      const dataOffset = commaIndex > -1 ? commaIndex + 1 : result.length;
      resolve(result.substring(dataOffset));
    };
    reader.onabort = () => reject(new Error("Read aborted"));
    reader.onerror = () => reject(reader.error);
    reader.readAsDataURL(blob);
  });
}
var streamCollector2;
var init_stream_collector2 = __esm({
  "node_modules/@smithy/fetch-http-handler/dist-es/stream-collector.js"() {
    init_dist_es11();
    streamCollector2 = async (stream) => {
      if (typeof Blob === "function" && stream instanceof Blob || stream.constructor?.name === "Blob") {
        if (Blob.prototype.arrayBuffer !== void 0) {
          return new Uint8Array(await stream.arrayBuffer());
        }
        return collectBlob(stream);
      }
      return collectStream(stream);
    };
  }
});

// node_modules/@smithy/fetch-http-handler/dist-es/index.js
var init_dist_es15 = __esm({
  "node_modules/@smithy/fetch-http-handler/dist-es/index.js"() {
    init_fetch_http_handler();
    init_stream_collector2();
  }
});

// node_modules/@smithy/util-hex-encoding/dist-es/index.js
function fromHex(encoded) {
  if (encoded.length % 2 !== 0) {
    throw new Error("Hex encoded strings must have an even number length");
  }
  const out = new Uint8Array(encoded.length / 2);
  for (let i6 = 0; i6 < encoded.length; i6 += 2) {
    const encodedByte = encoded.slice(i6, i6 + 2).toLowerCase();
    if (encodedByte in HEX_TO_SHORT) {
      out[i6 / 2] = HEX_TO_SHORT[encodedByte];
    } else {
      throw new Error(`Cannot decode unrecognized sequence ${encodedByte} as hexadecimal`);
    }
  }
  return out;
}
function toHex(bytes) {
  let out = "";
  for (let i6 = 0; i6 < bytes.byteLength; i6++) {
    out += SHORT_TO_HEX[bytes[i6]];
  }
  return out;
}
var SHORT_TO_HEX, HEX_TO_SHORT;
var init_dist_es16 = __esm({
  "node_modules/@smithy/util-hex-encoding/dist-es/index.js"() {
    SHORT_TO_HEX = {};
    HEX_TO_SHORT = {};
    for (let i6 = 0; i6 < 256; i6++) {
      let encodedByte = i6.toString(16).toLowerCase();
      if (encodedByte.length === 1) {
        encodedByte = `0${encodedByte}`;
      }
      SHORT_TO_HEX[i6] = encodedByte;
      HEX_TO_SHORT[encodedByte] = i6;
    }
  }
});

// node_modules/@smithy/util-stream/dist-es/sdk-stream-mixin.browser.js
var ERR_MSG_STREAM_HAS_BEEN_TRANSFORMED, sdkStreamMixin, isBlobInstance;
var init_sdk_stream_mixin_browser = __esm({
  "node_modules/@smithy/util-stream/dist-es/sdk-stream-mixin.browser.js"() {
    init_dist_es15();
    init_dist_es11();
    init_dist_es16();
    init_dist_es10();
    init_stream_type_check();
    ERR_MSG_STREAM_HAS_BEEN_TRANSFORMED = "The stream has already been transformed.";
    sdkStreamMixin = (stream) => {
      if (!isBlobInstance(stream) && !isReadableStream(stream)) {
        const name = stream?.__proto__?.constructor?.name || stream;
        throw new Error(`Unexpected stream implementation, expect Blob or ReadableStream, got ${name}`);
      }
      let transformed = false;
      const transformToByteArray = async () => {
        if (transformed) {
          throw new Error(ERR_MSG_STREAM_HAS_BEEN_TRANSFORMED);
        }
        transformed = true;
        return await streamCollector2(stream);
      };
      const blobToWebStream = (blob) => {
        if (typeof blob.stream !== "function") {
          throw new Error("Cannot transform payload Blob to web stream. Please make sure the Blob.stream() is polyfilled.\nIf you are using React Native, this API is not yet supported, see: https://react-native.canny.io/feature-requests/p/fetch-streaming-body");
        }
        return blob.stream();
      };
      return Object.assign(stream, {
        transformToByteArray,
        transformToString: async (encoding) => {
          const buf = await transformToByteArray();
          if (encoding === "base64") {
            return toBase64(buf);
          } else if (encoding === "hex") {
            return toHex(buf);
          } else if (encoding === void 0 || encoding === "utf8" || encoding === "utf-8") {
            return toUtf8(buf);
          } else if (typeof TextDecoder === "function") {
            return new TextDecoder(encoding).decode(buf);
          } else {
            throw new Error("TextDecoder is not available, please make sure polyfill is provided.");
          }
        },
        transformToWebStream: () => {
          if (transformed) {
            throw new Error(ERR_MSG_STREAM_HAS_BEEN_TRANSFORMED);
          }
          transformed = true;
          if (isBlobInstance(stream)) {
            return blobToWebStream(stream);
          } else if (isReadableStream(stream)) {
            return stream;
          } else {
            throw new Error(`Cannot transform payload to web stream, got ${stream}`);
          }
        }
      });
    };
    isBlobInstance = (stream) => typeof Blob === "function" && stream instanceof Blob;
  }
});

// node_modules/@smithy/util-stream/dist-es/sdk-stream-mixin.js
import { Readable as Readable2 } from "stream";
var ERR_MSG_STREAM_HAS_BEEN_TRANSFORMED2, sdkStreamMixin2;
var init_sdk_stream_mixin = __esm({
  "node_modules/@smithy/util-stream/dist-es/sdk-stream-mixin.js"() {
    init_dist_es14();
    init_dist_es9();
    init_sdk_stream_mixin_browser();
    ERR_MSG_STREAM_HAS_BEEN_TRANSFORMED2 = "The stream has already been transformed.";
    sdkStreamMixin2 = (stream) => {
      if (!(stream instanceof Readable2)) {
        try {
          return sdkStreamMixin(stream);
        } catch (e6) {
          const name = stream?.__proto__?.constructor?.name || stream;
          throw new Error(`Unexpected stream implementation, expect Stream.Readable instance, got ${name}`);
        }
      }
      let transformed = false;
      const transformToByteArray = async () => {
        if (transformed) {
          throw new Error(ERR_MSG_STREAM_HAS_BEEN_TRANSFORMED2);
        }
        transformed = true;
        return await streamCollector(stream);
      };
      return Object.assign(stream, {
        transformToByteArray,
        transformToString: async (encoding) => {
          const buf = await transformToByteArray();
          if (encoding === void 0 || Buffer.isEncoding(encoding)) {
            return fromArrayBuffer(buf.buffer, buf.byteOffset, buf.byteLength).toString(encoding);
          } else {
            const decoder = new TextDecoder(encoding);
            return decoder.decode(buf);
          }
        },
        transformToWebStream: () => {
          if (transformed) {
            throw new Error(ERR_MSG_STREAM_HAS_BEEN_TRANSFORMED2);
          }
          if (stream.readableFlowing !== null) {
            throw new Error("The stream has been consumed by other callbacks.");
          }
          if (typeof Readable2.toWeb !== "function") {
            throw new Error("Readable.toWeb() is not supported. Please ensure a polyfill is available.");
          }
          transformed = true;
          return Readable2.toWeb(stream);
        }
      });
    };
  }
});

// node_modules/@smithy/util-stream/dist-es/splitStream.js
var init_splitStream = __esm({
  "node_modules/@smithy/util-stream/dist-es/splitStream.js"() {
  }
});

// node_modules/@smithy/util-stream/dist-es/index.js
var init_dist_es17 = __esm({
  "node_modules/@smithy/util-stream/dist-es/index.js"() {
    init_Uint8ArrayBlobAdapter();
    init_ChecksumStream();
    init_createChecksumStream();
    init_createBufferedReadable();
    init_getAwsChunkedEncodingStream();
    init_headStream();
    init_sdk_stream_mixin();
    init_splitStream();
    init_stream_type_check();
  }
});

// node_modules/@smithy/core/dist-es/submodules/protocols/collect-stream-body.js
var collectBody;
var init_collect_stream_body = __esm({
  "node_modules/@smithy/core/dist-es/submodules/protocols/collect-stream-body.js"() {
    init_dist_es17();
    collectBody = async (streamBody = new Uint8Array(), context) => {
      if (streamBody instanceof Uint8Array) {
        return Uint8ArrayBlobAdapter.mutate(streamBody);
      }
      if (!streamBody) {
        return Uint8ArrayBlobAdapter.mutate(new Uint8Array());
      }
      const fromContext = context.streamCollector(streamBody);
      return Uint8ArrayBlobAdapter.mutate(await fromContext);
    };
  }
});

// node_modules/@smithy/core/dist-es/submodules/protocols/extended-encode-uri-component.js
function extendedEncodeURIComponent(str) {
  return encodeURIComponent(str).replace(/[!'()*]/g, function(c6) {
    return "%" + c6.charCodeAt(0).toString(16).toUpperCase();
  });
}
var init_extended_encode_uri_component = __esm({
  "node_modules/@smithy/core/dist-es/submodules/protocols/extended-encode-uri-component.js"() {
  }
});

// node_modules/@smithy/core/dist-es/submodules/schema/deref.js
var deref;
var init_deref = __esm({
  "node_modules/@smithy/core/dist-es/submodules/schema/deref.js"() {
    deref = (schemaRef) => {
      if (typeof schemaRef === "function") {
        return schemaRef();
      }
      return schemaRef;
    };
  }
});

// node_modules/@smithy/core/dist-es/submodules/schema/schemas/operation.js
var operation;
var init_operation = __esm({
  "node_modules/@smithy/core/dist-es/submodules/schema/schemas/operation.js"() {
    operation = (namespace, name, traits, input, output) => ({
      name,
      namespace,
      traits,
      input,
      output
    });
  }
});

// node_modules/@smithy/core/dist-es/submodules/schema/middleware/schemaDeserializationMiddleware.js
var schemaDeserializationMiddleware, findHeader;
var init_schemaDeserializationMiddleware = __esm({
  "node_modules/@smithy/core/dist-es/submodules/schema/middleware/schemaDeserializationMiddleware.js"() {
    init_dist_es2();
    init_dist_es6();
    init_operation();
    schemaDeserializationMiddleware = (config) => (next, context) => async (args) => {
      const { response } = await next(args);
      const { operationSchema } = getSmithyContext(context);
      const [, ns, n6, t6, i6, o6] = operationSchema ?? [];
      try {
        const parsed = await config.protocol.deserializeResponse(operation(ns, n6, t6, i6, o6), {
          ...config,
          ...context
        }, response);
        return {
          response,
          output: parsed
        };
      } catch (error) {
        Object.defineProperty(error, "$response", {
          value: response,
          enumerable: false,
          writable: false,
          configurable: false
        });
        if (!("$metadata" in error)) {
          const hint = `Deserialization error: to see the raw response, inspect the hidden field {error}.$response on this object.`;
          try {
            error.message += "\n  " + hint;
          } catch (e6) {
            if (!context.logger || context.logger?.constructor?.name === "NoOpLogger") {
              console.warn(hint);
            } else {
              context.logger?.warn?.(hint);
            }
          }
          if (typeof error.$responseBodyText !== "undefined") {
            if (error.$response) {
              error.$response.body = error.$responseBodyText;
            }
          }
          try {
            if (HttpResponse.isInstance(response)) {
              const { headers = {} } = response;
              const headerEntries = Object.entries(headers);
              error.$metadata = {
                httpStatusCode: response.statusCode,
                requestId: findHeader(/^x-[\w-]+-request-?id$/, headerEntries),
                extendedRequestId: findHeader(/^x-[\w-]+-id-2$/, headerEntries),
                cfId: findHeader(/^x-[\w-]+-cf-id$/, headerEntries)
              };
            }
          } catch (e6) {
          }
        }
        throw error;
      }
    };
    findHeader = (pattern, headers) => {
      return (headers.find(([k6]) => {
        return k6.match(pattern);
      }) || [void 0, void 0])[1];
    };
  }
});

// node_modules/@smithy/core/dist-es/submodules/schema/middleware/schemaSerializationMiddleware.js
var schemaSerializationMiddleware;
var init_schemaSerializationMiddleware = __esm({
  "node_modules/@smithy/core/dist-es/submodules/schema/middleware/schemaSerializationMiddleware.js"() {
    init_dist_es6();
    init_operation();
    schemaSerializationMiddleware = (config) => (next, context) => async (args) => {
      const { operationSchema } = getSmithyContext(context);
      const [, ns, n6, t6, i6, o6] = operationSchema ?? [];
      const endpoint = context.endpointV2?.url && config.urlParser ? async () => config.urlParser(context.endpointV2.url) : config.endpoint;
      const request2 = await config.protocol.serializeRequest(operation(ns, n6, t6, i6, o6), args.input, {
        ...config,
        ...context,
        endpoint
      });
      return next({
        ...args,
        request: request2
      });
    };
  }
});

// node_modules/@smithy/core/dist-es/submodules/schema/middleware/getSchemaSerdePlugin.js
function getSchemaSerdePlugin(config) {
  return {
    applyToStack: (commandStack) => {
      commandStack.add(schemaSerializationMiddleware(config), serializerMiddlewareOption2);
      commandStack.add(schemaDeserializationMiddleware(config), deserializerMiddlewareOption);
      config.protocol.setSerdeContext(config);
    }
  };
}
var deserializerMiddlewareOption, serializerMiddlewareOption2;
var init_getSchemaSerdePlugin = __esm({
  "node_modules/@smithy/core/dist-es/submodules/schema/middleware/getSchemaSerdePlugin.js"() {
    init_schemaDeserializationMiddleware();
    init_schemaSerializationMiddleware();
    deserializerMiddlewareOption = {
      name: "deserializerMiddleware",
      step: "deserialize",
      tags: ["DESERIALIZER"],
      override: true
    };
    serializerMiddlewareOption2 = {
      name: "serializerMiddleware",
      step: "serialize",
      tags: ["SERIALIZER"],
      override: true
    };
  }
});

// node_modules/@smithy/core/dist-es/submodules/schema/schemas/Schema.js
var init_Schema = __esm({
  "node_modules/@smithy/core/dist-es/submodules/schema/schemas/Schema.js"() {
  }
});

// node_modules/@smithy/core/dist-es/submodules/schema/schemas/ListSchema.js
var init_ListSchema = __esm({
  "node_modules/@smithy/core/dist-es/submodules/schema/schemas/ListSchema.js"() {
  }
});

// node_modules/@smithy/core/dist-es/submodules/schema/schemas/MapSchema.js
var init_MapSchema = __esm({
  "node_modules/@smithy/core/dist-es/submodules/schema/schemas/MapSchema.js"() {
  }
});

// node_modules/@smithy/core/dist-es/submodules/schema/schemas/OperationSchema.js
var init_OperationSchema = __esm({
  "node_modules/@smithy/core/dist-es/submodules/schema/schemas/OperationSchema.js"() {
  }
});

// node_modules/@smithy/core/dist-es/submodules/schema/schemas/StructureSchema.js
var init_StructureSchema = __esm({
  "node_modules/@smithy/core/dist-es/submodules/schema/schemas/StructureSchema.js"() {
  }
});

// node_modules/@smithy/core/dist-es/submodules/schema/schemas/ErrorSchema.js
var init_ErrorSchema = __esm({
  "node_modules/@smithy/core/dist-es/submodules/schema/schemas/ErrorSchema.js"() {
  }
});

// node_modules/@smithy/core/dist-es/submodules/schema/schemas/translateTraits.js
function translateTraits(indicator) {
  if (typeof indicator === "object") {
    return indicator;
  }
  indicator = indicator | 0;
  const traits = {};
  let i6 = 0;
  for (const trait of [
    "httpLabel",
    "idempotent",
    "idempotencyToken",
    "sensitive",
    "httpPayload",
    "httpResponseCode",
    "httpQueryParams"
  ]) {
    if ((indicator >> i6++ & 1) === 1) {
      traits[trait] = 1;
    }
  }
  return traits;
}
var init_translateTraits = __esm({
  "node_modules/@smithy/core/dist-es/submodules/schema/schemas/translateTraits.js"() {
  }
});

// node_modules/@smithy/core/dist-es/submodules/schema/schemas/NormalizedSchema.js
function member(memberSchema, memberName) {
  if (memberSchema instanceof NormalizedSchema) {
    return Object.assign(memberSchema, {
      memberName,
      _isMemberSchema: true
    });
  }
  const internalCtorAccess = NormalizedSchema;
  return new internalCtorAccess(memberSchema, memberName);
}
var NormalizedSchema, isMemberSchema, isStaticSchema;
var init_NormalizedSchema = __esm({
  "node_modules/@smithy/core/dist-es/submodules/schema/schemas/NormalizedSchema.js"() {
    init_deref();
    init_translateTraits();
    NormalizedSchema = class _NormalizedSchema {
      ref;
      memberName;
      static symbol = /* @__PURE__ */ Symbol.for("@smithy/nor");
      symbol = _NormalizedSchema.symbol;
      name;
      schema;
      _isMemberSchema;
      traits;
      memberTraits;
      normalizedTraits;
      constructor(ref, memberName) {
        this.ref = ref;
        this.memberName = memberName;
        const traitStack = [];
        let _ref = ref;
        let schema = ref;
        this._isMemberSchema = false;
        while (isMemberSchema(_ref)) {
          traitStack.push(_ref[1]);
          _ref = _ref[0];
          schema = deref(_ref);
          this._isMemberSchema = true;
        }
        if (traitStack.length > 0) {
          this.memberTraits = {};
          for (let i6 = traitStack.length - 1; i6 >= 0; --i6) {
            const traitSet = traitStack[i6];
            Object.assign(this.memberTraits, translateTraits(traitSet));
          }
        } else {
          this.memberTraits = 0;
        }
        if (schema instanceof _NormalizedSchema) {
          const computedMemberTraits = this.memberTraits;
          Object.assign(this, schema);
          this.memberTraits = Object.assign({}, computedMemberTraits, schema.getMemberTraits(), this.getMemberTraits());
          this.normalizedTraits = void 0;
          this.memberName = memberName ?? schema.memberName;
          return;
        }
        this.schema = deref(schema);
        if (isStaticSchema(this.schema)) {
          this.name = `${this.schema[1]}#${this.schema[2]}`;
          this.traits = this.schema[3];
        } else {
          this.name = this.memberName ?? String(schema);
          this.traits = 0;
        }
        if (this._isMemberSchema && !memberName) {
          throw new Error(`@smithy/core/schema - NormalizedSchema member init ${this.getName(true)} missing member name.`);
        }
      }
      static [Symbol.hasInstance](lhs) {
        const isPrototype = this.prototype.isPrototypeOf(lhs);
        if (!isPrototype && typeof lhs === "object" && lhs !== null) {
          const ns = lhs;
          return ns.symbol === this.symbol;
        }
        return isPrototype;
      }
      static of(ref) {
        const sc = deref(ref);
        if (sc instanceof _NormalizedSchema) {
          return sc;
        }
        if (isMemberSchema(sc)) {
          const [ns, traits] = sc;
          if (ns instanceof _NormalizedSchema) {
            Object.assign(ns.getMergedTraits(), translateTraits(traits));
            return ns;
          }
          throw new Error(`@smithy/core/schema - may not init unwrapped member schema=${JSON.stringify(ref, null, 2)}.`);
        }
        return new _NormalizedSchema(sc);
      }
      getSchema() {
        const sc = this.schema;
        if (sc[0] === 0) {
          return sc[4];
        }
        return sc;
      }
      getName(withNamespace = false) {
        const { name } = this;
        const short = !withNamespace && name && name.includes("#");
        return short ? name.split("#")[1] : name || void 0;
      }
      getMemberName() {
        return this.memberName;
      }
      isMemberSchema() {
        return this._isMemberSchema;
      }
      isListSchema() {
        const sc = this.getSchema();
        return typeof sc === "number" ? sc >= 64 && sc < 128 : sc[0] === 1;
      }
      isMapSchema() {
        const sc = this.getSchema();
        return typeof sc === "number" ? sc >= 128 && sc <= 255 : sc[0] === 2;
      }
      isStructSchema() {
        const sc = this.getSchema();
        const id = sc[0];
        return id === 3 || id === -3 || id === 4;
      }
      isUnionSchema() {
        const sc = this.getSchema();
        return sc[0] === 4;
      }
      isBlobSchema() {
        const sc = this.getSchema();
        return sc === 21 || sc === 42;
      }
      isTimestampSchema() {
        const sc = this.getSchema();
        return typeof sc === "number" && sc >= 4 && sc <= 7;
      }
      isUnitSchema() {
        return this.getSchema() === "unit";
      }
      isDocumentSchema() {
        return this.getSchema() === 15;
      }
      isStringSchema() {
        return this.getSchema() === 0;
      }
      isBooleanSchema() {
        return this.getSchema() === 2;
      }
      isNumericSchema() {
        return this.getSchema() === 1;
      }
      isBigIntegerSchema() {
        return this.getSchema() === 17;
      }
      isBigDecimalSchema() {
        return this.getSchema() === 19;
      }
      isStreaming() {
        const { streaming } = this.getMergedTraits();
        return !!streaming || this.getSchema() === 42;
      }
      isIdempotencyToken() {
        const match = (traits2) => (traits2 & 4) === 4 || !!traits2?.idempotencyToken;
        const { normalizedTraits, traits, memberTraits } = this;
        return match(normalizedTraits) || match(traits) || match(memberTraits);
      }
      getMergedTraits() {
        return this.normalizedTraits ?? (this.normalizedTraits = {
          ...this.getOwnTraits(),
          ...this.getMemberTraits()
        });
      }
      getMemberTraits() {
        return translateTraits(this.memberTraits);
      }
      getOwnTraits() {
        return translateTraits(this.traits);
      }
      getKeySchema() {
        const [isDoc, isMap] = [this.isDocumentSchema(), this.isMapSchema()];
        if (!isDoc && !isMap) {
          throw new Error(`@smithy/core/schema - cannot get key for non-map: ${this.getName(true)}`);
        }
        const schema = this.getSchema();
        const memberSchema = isDoc ? 15 : schema[4] ?? 0;
        return member([memberSchema, 0], "key");
      }
      getValueSchema() {
        const sc = this.getSchema();
        const [isDoc, isMap, isList] = [this.isDocumentSchema(), this.isMapSchema(), this.isListSchema()];
        const memberSchema = typeof sc === "number" ? 63 & sc : sc && typeof sc === "object" && (isMap || isList) ? sc[3 + sc[0]] : isDoc ? 15 : void 0;
        if (memberSchema != null) {
          return member([memberSchema, 0], isMap ? "value" : "member");
        }
        throw new Error(`@smithy/core/schema - ${this.getName(true)} has no value member.`);
      }
      getMemberSchema(memberName) {
        const struct = this.getSchema();
        if (this.isStructSchema() && struct[4].includes(memberName)) {
          const i6 = struct[4].indexOf(memberName);
          const memberSchema = struct[5][i6];
          return member(isMemberSchema(memberSchema) ? memberSchema : [memberSchema, 0], memberName);
        }
        if (this.isDocumentSchema()) {
          return member([15, 0], memberName);
        }
        throw new Error(`@smithy/core/schema - ${this.getName(true)} has no no member=${memberName}.`);
      }
      getMemberSchemas() {
        const buffer = {};
        try {
          for (const [k6, v7] of this.structIterator()) {
            buffer[k6] = v7;
          }
        } catch (ignored) {
        }
        return buffer;
      }
      getEventStreamMember() {
        if (this.isStructSchema()) {
          for (const [memberName, memberSchema] of this.structIterator()) {
            if (memberSchema.isStreaming() && memberSchema.isStructSchema()) {
              return memberName;
            }
          }
        }
        return "";
      }
      *structIterator() {
        if (this.isUnitSchema()) {
          return;
        }
        if (!this.isStructSchema()) {
          throw new Error("@smithy/core/schema - cannot iterate non-struct schema.");
        }
        const struct = this.getSchema();
        for (let i6 = 0; i6 < struct[4].length; ++i6) {
          yield [struct[4][i6], member([struct[5][i6], 0], struct[4][i6])];
        }
      }
    };
    isMemberSchema = (sc) => Array.isArray(sc) && sc.length === 2;
    isStaticSchema = (sc) => Array.isArray(sc) && sc.length >= 5;
  }
});

// node_modules/@smithy/core/dist-es/submodules/schema/schemas/SimpleSchema.js
var init_SimpleSchema = __esm({
  "node_modules/@smithy/core/dist-es/submodules/schema/schemas/SimpleSchema.js"() {
  }
});

// node_modules/@smithy/core/dist-es/submodules/schema/schemas/sentinels.js
var init_sentinels2 = __esm({
  "node_modules/@smithy/core/dist-es/submodules/schema/schemas/sentinels.js"() {
  }
});

// node_modules/@smithy/core/dist-es/submodules/schema/TypeRegistry.js
var TypeRegistry;
var init_TypeRegistry = __esm({
  "node_modules/@smithy/core/dist-es/submodules/schema/TypeRegistry.js"() {
    TypeRegistry = class _TypeRegistry {
      namespace;
      schemas;
      exceptions;
      static registries = /* @__PURE__ */ new Map();
      constructor(namespace, schemas = /* @__PURE__ */ new Map(), exceptions = /* @__PURE__ */ new Map()) {
        this.namespace = namespace;
        this.schemas = schemas;
        this.exceptions = exceptions;
      }
      static for(namespace) {
        if (!_TypeRegistry.registries.has(namespace)) {
          _TypeRegistry.registries.set(namespace, new _TypeRegistry(namespace));
        }
        return _TypeRegistry.registries.get(namespace);
      }
      register(shapeId, schema) {
        const qualifiedName = this.normalizeShapeId(shapeId);
        const registry = _TypeRegistry.for(qualifiedName.split("#")[0]);
        registry.schemas.set(qualifiedName, schema);
      }
      getSchema(shapeId) {
        const id = this.normalizeShapeId(shapeId);
        if (!this.schemas.has(id)) {
          throw new Error(`@smithy/core/schema - schema not found for ${id}`);
        }
        return this.schemas.get(id);
      }
      registerError(es, ctor) {
        const $error = es;
        const registry = _TypeRegistry.for($error[1]);
        registry.schemas.set($error[1] + "#" + $error[2], $error);
        registry.exceptions.set($error, ctor);
      }
      getErrorCtor(es) {
        const $error = es;
        const registry = _TypeRegistry.for($error[1]);
        return registry.exceptions.get($error);
      }
      getBaseException() {
        for (const exceptionKey of this.exceptions.keys()) {
          if (Array.isArray(exceptionKey)) {
            const [, ns, name] = exceptionKey;
            const id = ns + "#" + name;
            if (id.startsWith("smithy.ts.sdk.synthetic.") && id.endsWith("ServiceException")) {
              return exceptionKey;
            }
          }
        }
        return void 0;
      }
      find(predicate) {
        return [...this.schemas.values()].find(predicate);
      }
      clear() {
        this.schemas.clear();
        this.exceptions.clear();
      }
      normalizeShapeId(shapeId) {
        if (shapeId.includes("#")) {
          return shapeId;
        }
        return this.namespace + "#" + shapeId;
      }
    };
  }
});

// node_modules/@smithy/core/dist-es/submodules/schema/index.js
var init_schema2 = __esm({
  "node_modules/@smithy/core/dist-es/submodules/schema/index.js"() {
    init_deref();
    init_getSchemaSerdePlugin();
    init_ListSchema();
    init_MapSchema();
    init_OperationSchema();
    init_operation();
    init_ErrorSchema();
    init_NormalizedSchema();
    init_Schema();
    init_SimpleSchema();
    init_StructureSchema();
    init_sentinels2();
    init_translateTraits();
    init_TypeRegistry();
  }
});

// node_modules/@smithy/core/dist-es/submodules/serde/copyDocumentWithTransform.js
var init_copyDocumentWithTransform = __esm({
  "node_modules/@smithy/core/dist-es/submodules/serde/copyDocumentWithTransform.js"() {
  }
});

// node_modules/@smithy/core/dist-es/submodules/serde/parse-utils.js
var expectNumber, MAX_FLOAT, expectFloat32, expectLong, expectShort, expectByte, expectSizedInt, castInt, strictParseDouble, strictParseFloat32, NUMBER_REGEX, parseNumber, strictParseShort, strictParseByte, stackTraceWarning, logger;
var init_parse_utils = __esm({
  "node_modules/@smithy/core/dist-es/submodules/serde/parse-utils.js"() {
    expectNumber = (value) => {
      if (value === null || value === void 0) {
        return void 0;
      }
      if (typeof value === "string") {
        const parsed = parseFloat(value);
        if (!Number.isNaN(parsed)) {
          if (String(parsed) !== String(value)) {
            logger.warn(stackTraceWarning(`Expected number but observed string: ${value}`));
          }
          return parsed;
        }
      }
      if (typeof value === "number") {
        return value;
      }
      throw new TypeError(`Expected number, got ${typeof value}: ${value}`);
    };
    MAX_FLOAT = Math.ceil(2 ** 127 * (2 - 2 ** -23));
    expectFloat32 = (value) => {
      const expected = expectNumber(value);
      if (expected !== void 0 && !Number.isNaN(expected) && expected !== Infinity && expected !== -Infinity) {
        if (Math.abs(expected) > MAX_FLOAT) {
          throw new TypeError(`Expected 32-bit float, got ${value}`);
        }
      }
      return expected;
    };
    expectLong = (value) => {
      if (value === null || value === void 0) {
        return void 0;
      }
      if (Number.isInteger(value) && !Number.isNaN(value)) {
        return value;
      }
      throw new TypeError(`Expected integer, got ${typeof value}: ${value}`);
    };
    expectShort = (value) => expectSizedInt(value, 16);
    expectByte = (value) => expectSizedInt(value, 8);
    expectSizedInt = (value, size) => {
      const expected = expectLong(value);
      if (expected !== void 0 && castInt(expected, size) !== expected) {
        throw new TypeError(`Expected ${size}-bit integer, got ${value}`);
      }
      return expected;
    };
    castInt = (value, size) => {
      switch (size) {
        case 32:
          return Int32Array.of(value)[0];
        case 16:
          return Int16Array.of(value)[0];
        case 8:
          return Int8Array.of(value)[0];
      }
    };
    strictParseDouble = (value) => {
      if (typeof value == "string") {
        return expectNumber(parseNumber(value));
      }
      return expectNumber(value);
    };
    strictParseFloat32 = (value) => {
      if (typeof value == "string") {
        return expectFloat32(parseNumber(value));
      }
      return expectFloat32(value);
    };
    NUMBER_REGEX = /(-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)|(-?Infinity)|(NaN)/g;
    parseNumber = (value) => {
      const matches = value.match(NUMBER_REGEX);
      if (matches === null || matches[0].length !== value.length) {
        throw new TypeError(`Expected real number, got implicit NaN`);
      }
      return parseFloat(value);
    };
    strictParseShort = (value) => {
      if (typeof value === "string") {
        return expectShort(parseNumber(value));
      }
      return expectShort(value);
    };
    strictParseByte = (value) => {
      if (typeof value === "string") {
        return expectByte(parseNumber(value));
      }
      return expectByte(value);
    };
    stackTraceWarning = (message) => {
      return String(new TypeError(message).stack || message).split("\n").slice(0, 5).filter((s6) => !s6.includes("stackTraceWarning")).join("\n");
    };
    logger = {
      warn: console.warn
    };
  }
});

// node_modules/@smithy/core/dist-es/submodules/serde/date-utils.js
function dateToUtcString(date2) {
  const year2 = date2.getUTCFullYear();
  const month = date2.getUTCMonth();
  const dayOfWeek = date2.getUTCDay();
  const dayOfMonthInt = date2.getUTCDate();
  const hoursInt = date2.getUTCHours();
  const minutesInt = date2.getUTCMinutes();
  const secondsInt = date2.getUTCSeconds();
  const dayOfMonthString = dayOfMonthInt < 10 ? `0${dayOfMonthInt}` : `${dayOfMonthInt}`;
  const hoursString = hoursInt < 10 ? `0${hoursInt}` : `${hoursInt}`;
  const minutesString = minutesInt < 10 ? `0${minutesInt}` : `${minutesInt}`;
  const secondsString = secondsInt < 10 ? `0${secondsInt}` : `${secondsInt}`;
  return `${DAYS[dayOfWeek]}, ${dayOfMonthString} ${MONTHS[month]} ${year2} ${hoursString}:${minutesString}:${secondsString} GMT`;
}
var DAYS, MONTHS, RFC3339, parseRfc3339DateTime, RFC3339_WITH_OFFSET, parseRfc3339DateTimeWithOffset, IMF_FIXDATE, RFC_850_DATE, ASC_TIME, parseRfc7231DateTime, parseEpochTimestamp, buildDate, parseTwoDigitYear, FIFTY_YEARS_IN_MILLIS, adjustRfc850Year, parseMonthByShortName, DAYS_IN_MONTH, validateDayOfMonth, isLeapYear, parseDateValue, parseMilliseconds, parseOffsetToMilliseconds, stripLeadingZeroes;
var init_date_utils = __esm({
  "node_modules/@smithy/core/dist-es/submodules/serde/date-utils.js"() {
    init_parse_utils();
    DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    RFC3339 = new RegExp(/^(\d{4})-(\d{2})-(\d{2})[tT](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?[zZ]$/);
    parseRfc3339DateTime = (value) => {
      if (value === null || value === void 0) {
        return void 0;
      }
      if (typeof value !== "string") {
        throw new TypeError("RFC-3339 date-times must be expressed as strings");
      }
      const match = RFC3339.exec(value);
      if (!match) {
        throw new TypeError("Invalid RFC-3339 date-time value");
      }
      const [_, yearStr, monthStr, dayStr, hours, minutes, seconds, fractionalMilliseconds] = match;
      const year2 = strictParseShort(stripLeadingZeroes(yearStr));
      const month = parseDateValue(monthStr, "month", 1, 12);
      const day = parseDateValue(dayStr, "day", 1, 31);
      return buildDate(year2, month, day, { hours, minutes, seconds, fractionalMilliseconds });
    };
    RFC3339_WITH_OFFSET = new RegExp(/^(\d{4})-(\d{2})-(\d{2})[tT](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(([-+]\d{2}\:\d{2})|[zZ])$/);
    parseRfc3339DateTimeWithOffset = (value) => {
      if (value === null || value === void 0) {
        return void 0;
      }
      if (typeof value !== "string") {
        throw new TypeError("RFC-3339 date-times must be expressed as strings");
      }
      const match = RFC3339_WITH_OFFSET.exec(value);
      if (!match) {
        throw new TypeError("Invalid RFC-3339 date-time value");
      }
      const [_, yearStr, monthStr, dayStr, hours, minutes, seconds, fractionalMilliseconds, offsetStr] = match;
      const year2 = strictParseShort(stripLeadingZeroes(yearStr));
      const month = parseDateValue(monthStr, "month", 1, 12);
      const day = parseDateValue(dayStr, "day", 1, 31);
      const date2 = buildDate(year2, month, day, { hours, minutes, seconds, fractionalMilliseconds });
      if (offsetStr.toUpperCase() != "Z") {
        date2.setTime(date2.getTime() - parseOffsetToMilliseconds(offsetStr));
      }
      return date2;
    };
    IMF_FIXDATE = new RegExp(/^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), (\d{2}) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (\d{4}) (\d{1,2}):(\d{2}):(\d{2})(?:\.(\d+))? GMT$/);
    RFC_850_DATE = new RegExp(/^(?:Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday), (\d{2})-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)-(\d{2}) (\d{1,2}):(\d{2}):(\d{2})(?:\.(\d+))? GMT$/);
    ASC_TIME = new RegExp(/^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) ( [1-9]|\d{2}) (\d{1,2}):(\d{2}):(\d{2})(?:\.(\d+))? (\d{4})$/);
    parseRfc7231DateTime = (value) => {
      if (value === null || value === void 0) {
        return void 0;
      }
      if (typeof value !== "string") {
        throw new TypeError("RFC-7231 date-times must be expressed as strings");
      }
      let match = IMF_FIXDATE.exec(value);
      if (match) {
        const [_, dayStr, monthStr, yearStr, hours, minutes, seconds, fractionalMilliseconds] = match;
        return buildDate(strictParseShort(stripLeadingZeroes(yearStr)), parseMonthByShortName(monthStr), parseDateValue(dayStr, "day", 1, 31), { hours, minutes, seconds, fractionalMilliseconds });
      }
      match = RFC_850_DATE.exec(value);
      if (match) {
        const [_, dayStr, monthStr, yearStr, hours, minutes, seconds, fractionalMilliseconds] = match;
        return adjustRfc850Year(buildDate(parseTwoDigitYear(yearStr), parseMonthByShortName(monthStr), parseDateValue(dayStr, "day", 1, 31), {
          hours,
          minutes,
          seconds,
          fractionalMilliseconds
        }));
      }
      match = ASC_TIME.exec(value);
      if (match) {
        const [_, monthStr, dayStr, hours, minutes, seconds, fractionalMilliseconds, yearStr] = match;
        return buildDate(strictParseShort(stripLeadingZeroes(yearStr)), parseMonthByShortName(monthStr), parseDateValue(dayStr.trimLeft(), "day", 1, 31), { hours, minutes, seconds, fractionalMilliseconds });
      }
      throw new TypeError("Invalid RFC-7231 date-time value");
    };
    parseEpochTimestamp = (value) => {
      if (value === null || value === void 0) {
        return void 0;
      }
      let valueAsDouble;
      if (typeof value === "number") {
        valueAsDouble = value;
      } else if (typeof value === "string") {
        valueAsDouble = strictParseDouble(value);
      } else if (typeof value === "object" && value.tag === 1) {
        valueAsDouble = value.value;
      } else {
        throw new TypeError("Epoch timestamps must be expressed as floating point numbers or their string representation");
      }
      if (Number.isNaN(valueAsDouble) || valueAsDouble === Infinity || valueAsDouble === -Infinity) {
        throw new TypeError("Epoch timestamps must be valid, non-Infinite, non-NaN numerics");
      }
      return new Date(Math.round(valueAsDouble * 1e3));
    };
    buildDate = (year2, month, day, time2) => {
      const adjustedMonth = month - 1;
      validateDayOfMonth(year2, adjustedMonth, day);
      return new Date(Date.UTC(year2, adjustedMonth, day, parseDateValue(time2.hours, "hour", 0, 23), parseDateValue(time2.minutes, "minute", 0, 59), parseDateValue(time2.seconds, "seconds", 0, 60), parseMilliseconds(time2.fractionalMilliseconds)));
    };
    parseTwoDigitYear = (value) => {
      const thisYear = (/* @__PURE__ */ new Date()).getUTCFullYear();
      const valueInThisCentury = Math.floor(thisYear / 100) * 100 + strictParseShort(stripLeadingZeroes(value));
      if (valueInThisCentury < thisYear) {
        return valueInThisCentury + 100;
      }
      return valueInThisCentury;
    };
    FIFTY_YEARS_IN_MILLIS = 50 * 365 * 24 * 60 * 60 * 1e3;
    adjustRfc850Year = (input) => {
      if (input.getTime() - (/* @__PURE__ */ new Date()).getTime() > FIFTY_YEARS_IN_MILLIS) {
        return new Date(Date.UTC(input.getUTCFullYear() - 100, input.getUTCMonth(), input.getUTCDate(), input.getUTCHours(), input.getUTCMinutes(), input.getUTCSeconds(), input.getUTCMilliseconds()));
      }
      return input;
    };
    parseMonthByShortName = (value) => {
      const monthIdx = MONTHS.indexOf(value);
      if (monthIdx < 0) {
        throw new TypeError(`Invalid month: ${value}`);
      }
      return monthIdx + 1;
    };
    DAYS_IN_MONTH = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    validateDayOfMonth = (year2, month, day) => {
      let maxDays = DAYS_IN_MONTH[month];
      if (month === 1 && isLeapYear(year2)) {
        maxDays = 29;
      }
      if (day > maxDays) {
        throw new TypeError(`Invalid day for ${MONTHS[month]} in ${year2}: ${day}`);
      }
    };
    isLeapYear = (year2) => {
      return year2 % 4 === 0 && (year2 % 100 !== 0 || year2 % 400 === 0);
    };
    parseDateValue = (value, type, lower, upper) => {
      const dateVal = strictParseByte(stripLeadingZeroes(value));
      if (dateVal < lower || dateVal > upper) {
        throw new TypeError(`${type} must be between ${lower} and ${upper}, inclusive`);
      }
      return dateVal;
    };
    parseMilliseconds = (value) => {
      if (value === null || value === void 0) {
        return 0;
      }
      return strictParseFloat32("0." + value) * 1e3;
    };
    parseOffsetToMilliseconds = (value) => {
      const directionStr = value[0];
      let direction = 1;
      if (directionStr == "+") {
        direction = 1;
      } else if (directionStr == "-") {
        direction = -1;
      } else {
        throw new TypeError(`Offset direction, ${directionStr}, must be "+" or "-"`);
      }
      const hour = Number(value.substring(1, 3));
      const minute = Number(value.substring(4, 6));
      return direction * (hour * 60 + minute) * 60 * 1e3;
    };
    stripLeadingZeroes = (value) => {
      let idx = 0;
      while (idx < value.length - 1 && value.charAt(idx) === "0") {
        idx++;
      }
      if (idx === 0) {
        return value;
      }
      return value.slice(idx);
    };
  }
});

// node_modules/@smithy/uuid/dist-es/randomUUID.js
import crypto2 from "crypto";
var randomUUID;
var init_randomUUID = __esm({
  "node_modules/@smithy/uuid/dist-es/randomUUID.js"() {
    randomUUID = crypto2.randomUUID.bind(crypto2);
  }
});

// node_modules/@smithy/uuid/dist-es/v4.js
var decimalToHex, v4;
var init_v4 = __esm({
  "node_modules/@smithy/uuid/dist-es/v4.js"() {
    init_randomUUID();
    decimalToHex = Array.from({ length: 256 }, (_, i6) => i6.toString(16).padStart(2, "0"));
    v4 = () => {
      if (randomUUID) {
        return randomUUID();
      }
      const rnds = new Uint8Array(16);
      crypto.getRandomValues(rnds);
      rnds[6] = rnds[6] & 15 | 64;
      rnds[8] = rnds[8] & 63 | 128;
      return decimalToHex[rnds[0]] + decimalToHex[rnds[1]] + decimalToHex[rnds[2]] + decimalToHex[rnds[3]] + "-" + decimalToHex[rnds[4]] + decimalToHex[rnds[5]] + "-" + decimalToHex[rnds[6]] + decimalToHex[rnds[7]] + "-" + decimalToHex[rnds[8]] + decimalToHex[rnds[9]] + "-" + decimalToHex[rnds[10]] + decimalToHex[rnds[11]] + decimalToHex[rnds[12]] + decimalToHex[rnds[13]] + decimalToHex[rnds[14]] + decimalToHex[rnds[15]];
    };
  }
});

// node_modules/@smithy/uuid/dist-es/index.js
var init_dist_es18 = __esm({
  "node_modules/@smithy/uuid/dist-es/index.js"() {
    init_v4();
  }
});

// node_modules/@smithy/core/dist-es/submodules/serde/generateIdempotencyToken.js
var init_generateIdempotencyToken = __esm({
  "node_modules/@smithy/core/dist-es/submodules/serde/generateIdempotencyToken.js"() {
    init_dist_es18();
  }
});

// node_modules/@smithy/core/dist-es/submodules/serde/lazy-json.js
var LazyJsonString;
var init_lazy_json = __esm({
  "node_modules/@smithy/core/dist-es/submodules/serde/lazy-json.js"() {
    LazyJsonString = function LazyJsonString2(val) {
      const str = Object.assign(new String(val), {
        deserializeJSON() {
          return JSON.parse(String(val));
        },
        toString() {
          return String(val);
        },
        toJSON() {
          return String(val);
        }
      });
      return str;
    };
    LazyJsonString.from = (object) => {
      if (object && typeof object === "object" && (object instanceof LazyJsonString || "deserializeJSON" in object)) {
        return object;
      } else if (typeof object === "string" || Object.getPrototypeOf(object) === String.prototype) {
        return LazyJsonString(String(object));
      }
      return LazyJsonString(JSON.stringify(object));
    };
    LazyJsonString.fromObject = LazyJsonString.from;
  }
});

// node_modules/@smithy/core/dist-es/submodules/serde/quote-header.js
function quoteHeader(part) {
  if (part.includes(",") || part.includes('"')) {
    part = `"${part.replace(/"/g, '\\"')}"`;
  }
  return part;
}
var init_quote_header = __esm({
  "node_modules/@smithy/core/dist-es/submodules/serde/quote-header.js"() {
  }
});

// node_modules/@smithy/core/dist-es/submodules/serde/schema-serde-lib/schema-date-utils.js
function range(v7, min, max) {
  const _v2 = Number(v7);
  if (_v2 < min || _v2 > max) {
    throw new Error(`Value ${_v2} out of range [${min}, ${max}]`);
  }
}
var ddd, mmm, time, date, year, RFC3339_WITH_OFFSET2, IMF_FIXDATE2, RFC_850_DATE2, ASC_TIME2, months, _parseEpochTimestamp, _parseRfc3339DateTimeWithOffset, _parseRfc7231DateTime;
var init_schema_date_utils = __esm({
  "node_modules/@smithy/core/dist-es/submodules/serde/schema-serde-lib/schema-date-utils.js"() {
    ddd = `(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)(?:[ne|u?r]?s?day)?`;
    mmm = `(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)`;
    time = `(\\d?\\d):(\\d{2}):(\\d{2})(?:\\.(\\d+))?`;
    date = `(\\d?\\d)`;
    year = `(\\d{4})`;
    RFC3339_WITH_OFFSET2 = new RegExp(/^(\d{4})-(\d\d)-(\d\d)[tT](\d\d):(\d\d):(\d\d)(\.(\d+))?(([-+]\d\d:\d\d)|[zZ])$/);
    IMF_FIXDATE2 = new RegExp(`^${ddd}, ${date} ${mmm} ${year} ${time} GMT$`);
    RFC_850_DATE2 = new RegExp(`^${ddd}, ${date}-${mmm}-(\\d\\d) ${time} GMT$`);
    ASC_TIME2 = new RegExp(`^${ddd} ${mmm} ( [1-9]|\\d\\d) ${time} ${year}$`);
    months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    _parseEpochTimestamp = (value) => {
      if (value == null) {
        return void 0;
      }
      let num = NaN;
      if (typeof value === "number") {
        num = value;
      } else if (typeof value === "string") {
        if (!/^-?\d*\.?\d+$/.test(value)) {
          throw new TypeError(`parseEpochTimestamp - numeric string invalid.`);
        }
        num = Number.parseFloat(value);
      } else if (typeof value === "object" && value.tag === 1) {
        num = value.value;
      }
      if (isNaN(num) || Math.abs(num) === Infinity) {
        throw new TypeError("Epoch timestamps must be valid finite numbers.");
      }
      return new Date(Math.round(num * 1e3));
    };
    _parseRfc3339DateTimeWithOffset = (value) => {
      if (value == null) {
        return void 0;
      }
      if (typeof value !== "string") {
        throw new TypeError("RFC3339 timestamps must be strings");
      }
      const matches = RFC3339_WITH_OFFSET2.exec(value);
      if (!matches) {
        throw new TypeError(`Invalid RFC3339 timestamp format ${value}`);
      }
      const [, yearStr, monthStr, dayStr, hours, minutes, seconds, , ms, offsetStr] = matches;
      range(monthStr, 1, 12);
      range(dayStr, 1, 31);
      range(hours, 0, 23);
      range(minutes, 0, 59);
      range(seconds, 0, 60);
      const date2 = new Date(Date.UTC(Number(yearStr), Number(monthStr) - 1, Number(dayStr), Number(hours), Number(minutes), Number(seconds), Number(ms) ? Math.round(parseFloat(`0.${ms}`) * 1e3) : 0));
      date2.setUTCFullYear(Number(yearStr));
      if (offsetStr.toUpperCase() != "Z") {
        const [, sign2, offsetH, offsetM] = /([+-])(\d\d):(\d\d)/.exec(offsetStr) || [void 0, "+", 0, 0];
        const scalar = sign2 === "-" ? 1 : -1;
        date2.setTime(date2.getTime() + scalar * (Number(offsetH) * 60 * 60 * 1e3 + Number(offsetM) * 60 * 1e3));
      }
      return date2;
    };
    _parseRfc7231DateTime = (value) => {
      if (value == null) {
        return void 0;
      }
      if (typeof value !== "string") {
        throw new TypeError("RFC7231 timestamps must be strings.");
      }
      let day;
      let month;
      let year2;
      let hour;
      let minute;
      let second;
      let fraction;
      let matches;
      if (matches = IMF_FIXDATE2.exec(value)) {
        [, day, month, year2, hour, minute, second, fraction] = matches;
      } else if (matches = RFC_850_DATE2.exec(value)) {
        [, day, month, year2, hour, minute, second, fraction] = matches;
        year2 = (Number(year2) + 1900).toString();
      } else if (matches = ASC_TIME2.exec(value)) {
        [, month, day, hour, minute, second, fraction, year2] = matches;
      }
      if (year2 && second) {
        const timestamp = Date.UTC(Number(year2), months.indexOf(month), Number(day), Number(hour), Number(minute), Number(second), fraction ? Math.round(parseFloat(`0.${fraction}`) * 1e3) : 0);
        range(day, 1, 31);
        range(hour, 0, 23);
        range(minute, 0, 59);
        range(second, 0, 60);
        const date2 = new Date(timestamp);
        date2.setUTCFullYear(Number(year2));
        return date2;
      }
      throw new TypeError(`Invalid RFC7231 date-time value ${value}.`);
    };
  }
});

// node_modules/@smithy/core/dist-es/submodules/serde/split-every.js
function splitEvery(value, delimiter, numDelimiters) {
  if (numDelimiters <= 0 || !Number.isInteger(numDelimiters)) {
    throw new Error("Invalid number of delimiters (" + numDelimiters + ") for splitEvery.");
  }
  const segments = value.split(delimiter);
  if (numDelimiters === 1) {
    return segments;
  }
  const compoundSegments = [];
  let currentSegment = "";
  for (let i6 = 0; i6 < segments.length; i6++) {
    if (currentSegment === "") {
      currentSegment = segments[i6];
    } else {
      currentSegment += delimiter + segments[i6];
    }
    if ((i6 + 1) % numDelimiters === 0) {
      compoundSegments.push(currentSegment);
      currentSegment = "";
    }
  }
  if (currentSegment !== "") {
    compoundSegments.push(currentSegment);
  }
  return compoundSegments;
}
var init_split_every = __esm({
  "node_modules/@smithy/core/dist-es/submodules/serde/split-every.js"() {
  }
});

// node_modules/@smithy/core/dist-es/submodules/serde/split-header.js
var splitHeader;
var init_split_header = __esm({
  "node_modules/@smithy/core/dist-es/submodules/serde/split-header.js"() {
    splitHeader = (value) => {
      const z2 = value.length;
      const values = [];
      let withinQuotes = false;
      let prevChar = void 0;
      let anchor = 0;
      for (let i6 = 0; i6 < z2; ++i6) {
        const char = value[i6];
        switch (char) {
          case `"`:
            if (prevChar !== "\\") {
              withinQuotes = !withinQuotes;
            }
            break;
          case ",":
            if (!withinQuotes) {
              values.push(value.slice(anchor, i6));
              anchor = i6 + 1;
            }
            break;
          default:
        }
        prevChar = char;
      }
      values.push(value.slice(anchor));
      return values.map((v7) => {
        v7 = v7.trim();
        const z3 = v7.length;
        if (z3 < 2) {
          return v7;
        }
        if (v7[0] === `"` && v7[z3 - 1] === `"`) {
          v7 = v7.slice(1, z3 - 1);
        }
        return v7.replace(/\\"/g, '"');
      });
    };
  }
});

// node_modules/@smithy/core/dist-es/submodules/serde/value/NumericValue.js
var format, NumericValue;
var init_NumericValue = __esm({
  "node_modules/@smithy/core/dist-es/submodules/serde/value/NumericValue.js"() {
    format = /^-?\d*(\.\d+)?$/;
    NumericValue = class _NumericValue {
      string;
      type;
      constructor(string, type) {
        this.string = string;
        this.type = type;
        if (!format.test(string)) {
          throw new Error(`@smithy/core/serde - NumericValue must only contain [0-9], at most one decimal point ".", and an optional negation prefix "-".`);
        }
      }
      toString() {
        return this.string;
      }
      static [Symbol.hasInstance](object) {
        if (!object || typeof object !== "object") {
          return false;
        }
        const _nv = object;
        return _NumericValue.prototype.isPrototypeOf(object) || _nv.type === "bigDecimal" && format.test(_nv.string);
      }
    };
  }
});

// node_modules/@smithy/core/dist-es/submodules/serde/index.js
var init_serde2 = __esm({
  "node_modules/@smithy/core/dist-es/submodules/serde/index.js"() {
    init_copyDocumentWithTransform();
    init_date_utils();
    init_generateIdempotencyToken();
    init_lazy_json();
    init_parse_utils();
    init_quote_header();
    init_schema_date_utils();
    init_split_every();
    init_split_header();
    init_NumericValue();
  }
});

// node_modules/@smithy/core/dist-es/submodules/protocols/SerdeContext.js
var SerdeContext;
var init_SerdeContext = __esm({
  "node_modules/@smithy/core/dist-es/submodules/protocols/SerdeContext.js"() {
    SerdeContext = class {
      serdeContext;
      setSerdeContext(serdeContext) {
        this.serdeContext = serdeContext;
      }
    };
  }
});

// node_modules/@smithy/core/dist-es/submodules/event-streams/EventStreamSerde.js
var EventStreamSerde;
var init_EventStreamSerde = __esm({
  "node_modules/@smithy/core/dist-es/submodules/event-streams/EventStreamSerde.js"() {
    init_dist_es10();
    EventStreamSerde = class {
      marshaller;
      serializer;
      deserializer;
      serdeContext;
      defaultContentType;
      constructor({ marshaller, serializer, deserializer, serdeContext, defaultContentType }) {
        this.marshaller = marshaller;
        this.serializer = serializer;
        this.deserializer = deserializer;
        this.serdeContext = serdeContext;
        this.defaultContentType = defaultContentType;
      }
      async serializeEventStream({ eventStream, requestSchema, initialRequest }) {
        const marshaller = this.marshaller;
        const eventStreamMember = requestSchema.getEventStreamMember();
        const unionSchema = requestSchema.getMemberSchema(eventStreamMember);
        const serializer = this.serializer;
        const defaultContentType = this.defaultContentType;
        const initialRequestMarker = /* @__PURE__ */ Symbol("initialRequestMarker");
        const eventStreamIterable = {
          async *[Symbol.asyncIterator]() {
            if (initialRequest) {
              const headers = {
                ":event-type": { type: "string", value: "initial-request" },
                ":message-type": { type: "string", value: "event" },
                ":content-type": { type: "string", value: defaultContentType }
              };
              serializer.write(requestSchema, initialRequest);
              const body = serializer.flush();
              yield {
                [initialRequestMarker]: true,
                headers,
                body
              };
            }
            for await (const page of eventStream) {
              yield page;
            }
          }
        };
        return marshaller.serialize(eventStreamIterable, (event) => {
          if (event[initialRequestMarker]) {
            return {
              headers: event.headers,
              body: event.body
            };
          }
          const unionMember = Object.keys(event).find((key) => {
            return key !== "__type";
          }) ?? "";
          const { additionalHeaders, body, eventType, explicitPayloadContentType } = this.writeEventBody(unionMember, unionSchema, event);
          const headers = {
            ":event-type": { type: "string", value: eventType },
            ":message-type": { type: "string", value: "event" },
            ":content-type": { type: "string", value: explicitPayloadContentType ?? defaultContentType },
            ...additionalHeaders
          };
          return {
            headers,
            body
          };
        });
      }
      async deserializeEventStream({ response, responseSchema, initialResponseContainer }) {
        const marshaller = this.marshaller;
        const eventStreamMember = responseSchema.getEventStreamMember();
        const unionSchema = responseSchema.getMemberSchema(eventStreamMember);
        const memberSchemas = unionSchema.getMemberSchemas();
        const initialResponseMarker = /* @__PURE__ */ Symbol("initialResponseMarker");
        const asyncIterable = marshaller.deserialize(response.body, async (event) => {
          const unionMember = Object.keys(event).find((key) => {
            return key !== "__type";
          }) ?? "";
          const body = event[unionMember].body;
          if (unionMember === "initial-response") {
            const dataObject = await this.deserializer.read(responseSchema, body);
            delete dataObject[eventStreamMember];
            return {
              [initialResponseMarker]: true,
              ...dataObject
            };
          } else if (unionMember in memberSchemas) {
            const eventStreamSchema = memberSchemas[unionMember];
            if (eventStreamSchema.isStructSchema()) {
              const out = {};
              let hasBindings = false;
              for (const [name, member2] of eventStreamSchema.structIterator()) {
                const { eventHeader, eventPayload } = member2.getMergedTraits();
                hasBindings = hasBindings || Boolean(eventHeader || eventPayload);
                if (eventPayload) {
                  if (member2.isBlobSchema()) {
                    out[name] = body;
                  } else if (member2.isStringSchema()) {
                    out[name] = (this.serdeContext?.utf8Encoder ?? toUtf8)(body);
                  } else if (member2.isStructSchema()) {
                    out[name] = await this.deserializer.read(member2, body);
                  }
                } else if (eventHeader) {
                  const value = event[unionMember].headers[name]?.value;
                  if (value != null) {
                    if (member2.isNumericSchema()) {
                      if (value && typeof value === "object" && "bytes" in value) {
                        out[name] = BigInt(value.toString());
                      } else {
                        out[name] = Number(value);
                      }
                    } else {
                      out[name] = value;
                    }
                  }
                }
              }
              if (hasBindings) {
                return {
                  [unionMember]: out
                };
              }
            }
            return {
              [unionMember]: await this.deserializer.read(eventStreamSchema, body)
            };
          } else {
            return {
              $unknown: event
            };
          }
        });
        const asyncIterator = asyncIterable[Symbol.asyncIterator]();
        const firstEvent = await asyncIterator.next();
        if (firstEvent.done) {
          return asyncIterable;
        }
        if (firstEvent.value?.[initialResponseMarker]) {
          if (!responseSchema) {
            throw new Error("@smithy::core/protocols - initial-response event encountered in event stream but no response schema given.");
          }
          for (const [key, value] of Object.entries(firstEvent.value)) {
            initialResponseContainer[key] = value;
          }
        }
        return {
          async *[Symbol.asyncIterator]() {
            if (!firstEvent?.value?.[initialResponseMarker]) {
              yield firstEvent.value;
            }
            while (true) {
              const { done, value } = await asyncIterator.next();
              if (done) {
                break;
              }
              yield value;
            }
          }
        };
      }
      writeEventBody(unionMember, unionSchema, event) {
        const serializer = this.serializer;
        let eventType = unionMember;
        let explicitPayloadMember = null;
        let explicitPayloadContentType;
        const isKnownSchema = (() => {
          const struct = unionSchema.getSchema();
          return struct[4].includes(unionMember);
        })();
        const additionalHeaders = {};
        if (!isKnownSchema) {
          const [type, value] = event[unionMember];
          eventType = type;
          serializer.write(15, value);
        } else {
          const eventSchema = unionSchema.getMemberSchema(unionMember);
          if (eventSchema.isStructSchema()) {
            for (const [memberName, memberSchema] of eventSchema.structIterator()) {
              const { eventHeader, eventPayload } = memberSchema.getMergedTraits();
              if (eventPayload) {
                explicitPayloadMember = memberName;
              } else if (eventHeader) {
                const value = event[unionMember][memberName];
                let type = "binary";
                if (memberSchema.isNumericSchema()) {
                  if ((-2) ** 31 <= value && value <= 2 ** 31 - 1) {
                    type = "integer";
                  } else {
                    type = "long";
                  }
                } else if (memberSchema.isTimestampSchema()) {
                  type = "timestamp";
                } else if (memberSchema.isStringSchema()) {
                  type = "string";
                } else if (memberSchema.isBooleanSchema()) {
                  type = "boolean";
                }
                if (value != null) {
                  additionalHeaders[memberName] = {
                    type,
                    value
                  };
                  delete event[unionMember][memberName];
                }
              }
            }
            if (explicitPayloadMember !== null) {
              const payloadSchema = eventSchema.getMemberSchema(explicitPayloadMember);
              if (payloadSchema.isBlobSchema()) {
                explicitPayloadContentType = "application/octet-stream";
              } else if (payloadSchema.isStringSchema()) {
                explicitPayloadContentType = "text/plain";
              }
              serializer.write(payloadSchema, event[unionMember][explicitPayloadMember]);
            } else {
              serializer.write(eventSchema, event[unionMember]);
            }
          } else {
            throw new Error("@smithy/core/event-streams - non-struct member not supported in event stream union.");
          }
        }
        const messageSerialization = serializer.flush();
        const body = typeof messageSerialization === "string" ? (this.serdeContext?.utf8Decoder ?? fromUtf8)(messageSerialization) : messageSerialization;
        return {
          body,
          eventType,
          explicitPayloadContentType,
          additionalHeaders
        };
      }
    };
  }
});

// node_modules/@smithy/core/dist-es/submodules/event-streams/index.js
var event_streams_exports = {};
__export(event_streams_exports, {
  EventStreamSerde: () => EventStreamSerde
});
var init_event_streams = __esm({
  "node_modules/@smithy/core/dist-es/submodules/event-streams/index.js"() {
    init_EventStreamSerde();
  }
});

// node_modules/@smithy/core/dist-es/submodules/protocols/HttpProtocol.js
var HttpProtocol;
var init_HttpProtocol = __esm({
  "node_modules/@smithy/core/dist-es/submodules/protocols/HttpProtocol.js"() {
    init_schema2();
    init_dist_es2();
    init_SerdeContext();
    HttpProtocol = class extends SerdeContext {
      options;
      constructor(options) {
        super();
        this.options = options;
      }
      getRequestType() {
        return HttpRequest;
      }
      getResponseType() {
        return HttpResponse;
      }
      setSerdeContext(serdeContext) {
        this.serdeContext = serdeContext;
        this.serializer.setSerdeContext(serdeContext);
        this.deserializer.setSerdeContext(serdeContext);
        if (this.getPayloadCodec()) {
          this.getPayloadCodec().setSerdeContext(serdeContext);
        }
      }
      updateServiceEndpoint(request2, endpoint) {
        if ("url" in endpoint) {
          request2.protocol = endpoint.url.protocol;
          request2.hostname = endpoint.url.hostname;
          request2.port = endpoint.url.port ? Number(endpoint.url.port) : void 0;
          request2.path = endpoint.url.pathname;
          request2.fragment = endpoint.url.hash || void 0;
          request2.username = endpoint.url.username || void 0;
          request2.password = endpoint.url.password || void 0;
          if (!request2.query) {
            request2.query = {};
          }
          for (const [k6, v7] of endpoint.url.searchParams.entries()) {
            request2.query[k6] = v7;
          }
          return request2;
        } else {
          request2.protocol = endpoint.protocol;
          request2.hostname = endpoint.hostname;
          request2.port = endpoint.port ? Number(endpoint.port) : void 0;
          request2.path = endpoint.path;
          request2.query = {
            ...endpoint.query
          };
          return request2;
        }
      }
      setHostPrefix(request2, operationSchema, input) {
        const inputNs = NormalizedSchema.of(operationSchema.input);
        const opTraits = translateTraits(operationSchema.traits ?? {});
        if (opTraits.endpoint) {
          let hostPrefix = opTraits.endpoint?.[0];
          if (typeof hostPrefix === "string") {
            const hostLabelInputs = [...inputNs.structIterator()].filter(([, member2]) => member2.getMergedTraits().hostLabel);
            for (const [name] of hostLabelInputs) {
              const replacement = input[name];
              if (typeof replacement !== "string") {
                throw new Error(`@smithy/core/schema - ${name} in input must be a string as hostLabel.`);
              }
              hostPrefix = hostPrefix.replace(`{${name}}`, replacement);
            }
            request2.hostname = hostPrefix + request2.hostname;
          }
        }
      }
      deserializeMetadata(output) {
        return {
          httpStatusCode: output.statusCode,
          requestId: output.headers["x-amzn-requestid"] ?? output.headers["x-amzn-request-id"] ?? output.headers["x-amz-request-id"],
          extendedRequestId: output.headers["x-amz-id-2"],
          cfId: output.headers["x-amz-cf-id"]
        };
      }
      async serializeEventStream({ eventStream, requestSchema, initialRequest }) {
        const eventStreamSerde = await this.loadEventStreamCapability();
        return eventStreamSerde.serializeEventStream({
          eventStream,
          requestSchema,
          initialRequest
        });
      }
      async deserializeEventStream({ response, responseSchema, initialResponseContainer }) {
        const eventStreamSerde = await this.loadEventStreamCapability();
        return eventStreamSerde.deserializeEventStream({
          response,
          responseSchema,
          initialResponseContainer
        });
      }
      async loadEventStreamCapability() {
        const { EventStreamSerde: EventStreamSerde2 } = await Promise.resolve().then(() => (init_event_streams(), event_streams_exports));
        return new EventStreamSerde2({
          marshaller: this.getEventStreamMarshaller(),
          serializer: this.serializer,
          deserializer: this.deserializer,
          serdeContext: this.serdeContext,
          defaultContentType: this.getDefaultContentType()
        });
      }
      getDefaultContentType() {
        throw new Error(`@smithy/core/protocols - ${this.constructor.name} getDefaultContentType() implementation missing.`);
      }
      async deserializeHttpMessage(schema, context, response, arg4, arg5) {
        void schema;
        void context;
        void response;
        void arg4;
        void arg5;
        return [];
      }
      getEventStreamMarshaller() {
        const context = this.serdeContext;
        if (!context.eventStreamMarshaller) {
          throw new Error("@smithy/core - HttpProtocol: eventStreamMarshaller missing in serdeContext.");
        }
        return context.eventStreamMarshaller;
      }
    };
  }
});

// node_modules/@smithy/core/dist-es/submodules/protocols/HttpBindingProtocol.js
var HttpBindingProtocol;
var init_HttpBindingProtocol = __esm({
  "node_modules/@smithy/core/dist-es/submodules/protocols/HttpBindingProtocol.js"() {
    init_schema2();
    init_serde2();
    init_dist_es2();
    init_dist_es17();
    init_collect_stream_body();
    init_extended_encode_uri_component();
    init_HttpProtocol();
    HttpBindingProtocol = class extends HttpProtocol {
      async serializeRequest(operationSchema, _input, context) {
        const input = {
          ..._input ?? {}
        };
        const serializer = this.serializer;
        const query = {};
        const headers = {};
        const endpoint = await context.endpoint();
        const ns = NormalizedSchema.of(operationSchema?.input);
        const schema = ns.getSchema();
        let hasNonHttpBindingMember = false;
        let payload;
        const request2 = new HttpRequest({
          protocol: "",
          hostname: "",
          port: void 0,
          path: "",
          fragment: void 0,
          query,
          headers,
          body: void 0
        });
        if (endpoint) {
          this.updateServiceEndpoint(request2, endpoint);
          this.setHostPrefix(request2, operationSchema, input);
          const opTraits = translateTraits(operationSchema.traits);
          if (opTraits.http) {
            request2.method = opTraits.http[0];
            const [path, search] = opTraits.http[1].split("?");
            if (request2.path == "/") {
              request2.path = path;
            } else {
              request2.path += path;
            }
            const traitSearchParams = new URLSearchParams(search ?? "");
            Object.assign(query, Object.fromEntries(traitSearchParams));
          }
        }
        for (const [memberName, memberNs] of ns.structIterator()) {
          const memberTraits = memberNs.getMergedTraits() ?? {};
          const inputMemberValue = input[memberName];
          if (inputMemberValue == null && !memberNs.isIdempotencyToken()) {
            continue;
          }
          if (memberTraits.httpPayload) {
            const isStreaming = memberNs.isStreaming();
            if (isStreaming) {
              const isEventStream = memberNs.isStructSchema();
              if (isEventStream) {
                if (input[memberName]) {
                  payload = await this.serializeEventStream({
                    eventStream: input[memberName],
                    requestSchema: ns
                  });
                }
              } else {
                payload = inputMemberValue;
              }
            } else {
              serializer.write(memberNs, inputMemberValue);
              payload = serializer.flush();
            }
            delete input[memberName];
          } else if (memberTraits.httpLabel) {
            serializer.write(memberNs, inputMemberValue);
            const replacement = serializer.flush();
            if (request2.path.includes(`{${memberName}+}`)) {
              request2.path = request2.path.replace(`{${memberName}+}`, replacement.split("/").map(extendedEncodeURIComponent).join("/"));
            } else if (request2.path.includes(`{${memberName}}`)) {
              request2.path = request2.path.replace(`{${memberName}}`, extendedEncodeURIComponent(replacement));
            }
            delete input[memberName];
          } else if (memberTraits.httpHeader) {
            serializer.write(memberNs, inputMemberValue);
            headers[memberTraits.httpHeader.toLowerCase()] = String(serializer.flush());
            delete input[memberName];
          } else if (typeof memberTraits.httpPrefixHeaders === "string") {
            for (const [key, val] of Object.entries(inputMemberValue)) {
              const amalgam = memberTraits.httpPrefixHeaders + key;
              serializer.write([memberNs.getValueSchema(), { httpHeader: amalgam }], val);
              headers[amalgam.toLowerCase()] = serializer.flush();
            }
            delete input[memberName];
          } else if (memberTraits.httpQuery || memberTraits.httpQueryParams) {
            this.serializeQuery(memberNs, inputMemberValue, query);
            delete input[memberName];
          } else {
            hasNonHttpBindingMember = true;
          }
        }
        if (hasNonHttpBindingMember && input) {
          serializer.write(schema, input);
          payload = serializer.flush();
        }
        request2.headers = headers;
        request2.query = query;
        request2.body = payload;
        return request2;
      }
      serializeQuery(ns, data, query) {
        const serializer = this.serializer;
        const traits = ns.getMergedTraits();
        if (traits.httpQueryParams) {
          for (const [key, val] of Object.entries(data)) {
            if (!(key in query)) {
              const valueSchema = ns.getValueSchema();
              Object.assign(valueSchema.getMergedTraits(), {
                ...traits,
                httpQuery: key,
                httpQueryParams: void 0
              });
              this.serializeQuery(valueSchema, val, query);
            }
          }
          return;
        }
        if (ns.isListSchema()) {
          const sparse = !!ns.getMergedTraits().sparse;
          const buffer = [];
          for (const item of data) {
            serializer.write([ns.getValueSchema(), traits], item);
            const serializable = serializer.flush();
            if (sparse || serializable !== void 0) {
              buffer.push(serializable);
            }
          }
          query[traits.httpQuery] = buffer;
        } else {
          serializer.write([ns, traits], data);
          query[traits.httpQuery] = serializer.flush();
        }
      }
      async deserializeResponse(operationSchema, context, response) {
        const deserializer = this.deserializer;
        const ns = NormalizedSchema.of(operationSchema.output);
        const dataObject = {};
        if (response.statusCode >= 300) {
          const bytes = await collectBody(response.body, context);
          if (bytes.byteLength > 0) {
            Object.assign(dataObject, await deserializer.read(15, bytes));
          }
          await this.handleError(operationSchema, context, response, dataObject, this.deserializeMetadata(response));
          throw new Error("@smithy/core/protocols - HTTP Protocol error handler failed to throw.");
        }
        for (const header in response.headers) {
          const value = response.headers[header];
          delete response.headers[header];
          response.headers[header.toLowerCase()] = value;
        }
        const nonHttpBindingMembers = await this.deserializeHttpMessage(ns, context, response, dataObject);
        if (nonHttpBindingMembers.length) {
          const bytes = await collectBody(response.body, context);
          if (bytes.byteLength > 0) {
            const dataFromBody = await deserializer.read(ns, bytes);
            for (const member2 of nonHttpBindingMembers) {
              dataObject[member2] = dataFromBody[member2];
            }
          }
        } else if (nonHttpBindingMembers.discardResponseBody) {
          await collectBody(response.body, context);
        }
        dataObject.$metadata = this.deserializeMetadata(response);
        return dataObject;
      }
      async deserializeHttpMessage(schema, context, response, arg4, arg5) {
        let dataObject;
        if (arg4 instanceof Set) {
          dataObject = arg5;
        } else {
          dataObject = arg4;
        }
        let discardResponseBody = true;
        const deserializer = this.deserializer;
        const ns = NormalizedSchema.of(schema);
        const nonHttpBindingMembers = [];
        for (const [memberName, memberSchema] of ns.structIterator()) {
          const memberTraits = memberSchema.getMemberTraits();
          if (memberTraits.httpPayload) {
            discardResponseBody = false;
            const isStreaming = memberSchema.isStreaming();
            if (isStreaming) {
              const isEventStream = memberSchema.isStructSchema();
              if (isEventStream) {
                dataObject[memberName] = await this.deserializeEventStream({
                  response,
                  responseSchema: ns
                });
              } else {
                dataObject[memberName] = sdkStreamMixin2(response.body);
              }
            } else if (response.body) {
              const bytes = await collectBody(response.body, context);
              if (bytes.byteLength > 0) {
                dataObject[memberName] = await deserializer.read(memberSchema, bytes);
              }
            }
          } else if (memberTraits.httpHeader) {
            const key = String(memberTraits.httpHeader).toLowerCase();
            const value = response.headers[key];
            if (null != value) {
              if (memberSchema.isListSchema()) {
                const headerListValueSchema = memberSchema.getValueSchema();
                headerListValueSchema.getMergedTraits().httpHeader = key;
                let sections;
                if (headerListValueSchema.isTimestampSchema() && headerListValueSchema.getSchema() === 4) {
                  sections = splitEvery(value, ",", 2);
                } else {
                  sections = splitHeader(value);
                }
                const list = [];
                for (const section of sections) {
                  list.push(await deserializer.read(headerListValueSchema, section.trim()));
                }
                dataObject[memberName] = list;
              } else {
                dataObject[memberName] = await deserializer.read(memberSchema, value);
              }
            }
          } else if (memberTraits.httpPrefixHeaders !== void 0) {
            dataObject[memberName] = {};
            for (const [header, value] of Object.entries(response.headers)) {
              if (header.startsWith(memberTraits.httpPrefixHeaders)) {
                const valueSchema = memberSchema.getValueSchema();
                valueSchema.getMergedTraits().httpHeader = header;
                dataObject[memberName][header.slice(memberTraits.httpPrefixHeaders.length)] = await deserializer.read(valueSchema, value);
              }
            }
          } else if (memberTraits.httpResponseCode) {
            dataObject[memberName] = response.statusCode;
          } else {
            nonHttpBindingMembers.push(memberName);
          }
        }
        nonHttpBindingMembers.discardResponseBody = discardResponseBody;
        return nonHttpBindingMembers;
      }
    };
  }
});

// node_modules/@smithy/core/dist-es/submodules/protocols/RpcProtocol.js
var RpcProtocol;
var init_RpcProtocol = __esm({
  "node_modules/@smithy/core/dist-es/submodules/protocols/RpcProtocol.js"() {
    init_schema2();
    init_dist_es2();
    init_collect_stream_body();
    init_HttpProtocol();
    RpcProtocol = class extends HttpProtocol {
      async serializeRequest(operationSchema, input, context) {
        const serializer = this.serializer;
        const query = {};
        const headers = {};
        const endpoint = await context.endpoint();
        const ns = NormalizedSchema.of(operationSchema?.input);
        const schema = ns.getSchema();
        let payload;
        const request2 = new HttpRequest({
          protocol: "",
          hostname: "",
          port: void 0,
          path: "/",
          fragment: void 0,
          query,
          headers,
          body: void 0
        });
        if (endpoint) {
          this.updateServiceEndpoint(request2, endpoint);
          this.setHostPrefix(request2, operationSchema, input);
        }
        const _input = {
          ...input
        };
        if (input) {
          const eventStreamMember = ns.getEventStreamMember();
          if (eventStreamMember) {
            if (_input[eventStreamMember]) {
              const initialRequest = {};
              for (const [memberName, memberSchema] of ns.structIterator()) {
                if (memberName !== eventStreamMember && _input[memberName]) {
                  serializer.write(memberSchema, _input[memberName]);
                  initialRequest[memberName] = serializer.flush();
                }
              }
              payload = await this.serializeEventStream({
                eventStream: _input[eventStreamMember],
                requestSchema: ns,
                initialRequest
              });
            }
          } else {
            serializer.write(schema, _input);
            payload = serializer.flush();
          }
        }
        request2.headers = headers;
        request2.query = query;
        request2.body = payload;
        request2.method = "POST";
        return request2;
      }
      async deserializeResponse(operationSchema, context, response) {
        const deserializer = this.deserializer;
        const ns = NormalizedSchema.of(operationSchema.output);
        const dataObject = {};
        if (response.statusCode >= 300) {
          const bytes = await collectBody(response.body, context);
          if (bytes.byteLength > 0) {
            Object.assign(dataObject, await deserializer.read(15, bytes));
          }
          await this.handleError(operationSchema, context, response, dataObject, this.deserializeMetadata(response));
          throw new Error("@smithy/core/protocols - RPC Protocol error handler failed to throw.");
        }
        for (const header in response.headers) {
          const value = response.headers[header];
          delete response.headers[header];
          response.headers[header.toLowerCase()] = value;
        }
        const eventStreamMember = ns.getEventStreamMember();
        if (eventStreamMember) {
          dataObject[eventStreamMember] = await this.deserializeEventStream({
            response,
            responseSchema: ns,
            initialResponseContainer: dataObject
          });
        } else {
          const bytes = await collectBody(response.body, context);
          if (bytes.byteLength > 0) {
            Object.assign(dataObject, await deserializer.read(ns, bytes));
          }
        }
        dataObject.$metadata = this.deserializeMetadata(response);
        return dataObject;
      }
    };
  }
});

// node_modules/@smithy/core/dist-es/submodules/protocols/resolve-path.js
var init_resolve_path = __esm({
  "node_modules/@smithy/core/dist-es/submodules/protocols/resolve-path.js"() {
  }
});

// node_modules/@smithy/core/dist-es/submodules/protocols/requestBuilder.js
var init_requestBuilder = __esm({
  "node_modules/@smithy/core/dist-es/submodules/protocols/requestBuilder.js"() {
  }
});

// node_modules/@smithy/core/dist-es/submodules/protocols/serde/determineTimestampFormat.js
function determineTimestampFormat(ns, settings) {
  if (settings.timestampFormat.useTrait) {
    if (ns.isTimestampSchema() && (ns.getSchema() === 5 || ns.getSchema() === 6 || ns.getSchema() === 7)) {
      return ns.getSchema();
    }
  }
  const { httpLabel, httpPrefixHeaders, httpHeader, httpQuery } = ns.getMergedTraits();
  const bindingFormat = settings.httpBindings ? typeof httpPrefixHeaders === "string" || Boolean(httpHeader) ? 6 : Boolean(httpQuery) || Boolean(httpLabel) ? 5 : void 0 : void 0;
  return bindingFormat ?? settings.timestampFormat.default;
}
var init_determineTimestampFormat = __esm({
  "node_modules/@smithy/core/dist-es/submodules/protocols/serde/determineTimestampFormat.js"() {
  }
});

// node_modules/@smithy/core/dist-es/submodules/protocols/serde/FromStringShapeDeserializer.js
var FromStringShapeDeserializer;
var init_FromStringShapeDeserializer = __esm({
  "node_modules/@smithy/core/dist-es/submodules/protocols/serde/FromStringShapeDeserializer.js"() {
    init_schema2();
    init_serde2();
    init_dist_es11();
    init_dist_es10();
    init_SerdeContext();
    init_determineTimestampFormat();
    FromStringShapeDeserializer = class extends SerdeContext {
      settings;
      constructor(settings) {
        super();
        this.settings = settings;
      }
      read(_schema, data) {
        const ns = NormalizedSchema.of(_schema);
        if (ns.isListSchema()) {
          return splitHeader(data).map((item) => this.read(ns.getValueSchema(), item));
        }
        if (ns.isBlobSchema()) {
          return (this.serdeContext?.base64Decoder ?? fromBase64)(data);
        }
        if (ns.isTimestampSchema()) {
          const format2 = determineTimestampFormat(ns, this.settings);
          switch (format2) {
            case 5:
              return _parseRfc3339DateTimeWithOffset(data);
            case 6:
              return _parseRfc7231DateTime(data);
            case 7:
              return _parseEpochTimestamp(data);
            default:
              console.warn("Missing timestamp format, parsing value with Date constructor:", data);
              return new Date(data);
          }
        }
        if (ns.isStringSchema()) {
          const mediaType = ns.getMergedTraits().mediaType;
          let intermediateValue = data;
          if (mediaType) {
            if (ns.getMergedTraits().httpHeader) {
              intermediateValue = this.base64ToUtf8(intermediateValue);
            }
            const isJson = mediaType === "application/json" || mediaType.endsWith("+json");
            if (isJson) {
              intermediateValue = LazyJsonString.from(intermediateValue);
            }
            return intermediateValue;
          }
        }
        if (ns.isNumericSchema()) {
          return Number(data);
        }
        if (ns.isBigIntegerSchema()) {
          return BigInt(data);
        }
        if (ns.isBigDecimalSchema()) {
          return new NumericValue(data, "bigDecimal");
        }
        if (ns.isBooleanSchema()) {
          return String(data).toLowerCase() === "true";
        }
        return data;
      }
      base64ToUtf8(base64String) {
        return (this.serdeContext?.utf8Encoder ?? toUtf8)((this.serdeContext?.base64Decoder ?? fromBase64)(base64String));
      }
    };
  }
});

// node_modules/@smithy/core/dist-es/submodules/protocols/serde/HttpInterceptingShapeDeserializer.js
var HttpInterceptingShapeDeserializer;
var init_HttpInterceptingShapeDeserializer = __esm({
  "node_modules/@smithy/core/dist-es/submodules/protocols/serde/HttpInterceptingShapeDeserializer.js"() {
    init_schema2();
    init_dist_es10();
    init_SerdeContext();
    init_FromStringShapeDeserializer();
    HttpInterceptingShapeDeserializer = class extends SerdeContext {
      codecDeserializer;
      stringDeserializer;
      constructor(codecDeserializer, codecSettings) {
        super();
        this.codecDeserializer = codecDeserializer;
        this.stringDeserializer = new FromStringShapeDeserializer(codecSettings);
      }
      setSerdeContext(serdeContext) {
        this.stringDeserializer.setSerdeContext(serdeContext);
        this.codecDeserializer.setSerdeContext(serdeContext);
        this.serdeContext = serdeContext;
      }
      read(schema, data) {
        const ns = NormalizedSchema.of(schema);
        const traits = ns.getMergedTraits();
        const toString = this.serdeContext?.utf8Encoder ?? toUtf8;
        if (traits.httpHeader || traits.httpResponseCode) {
          return this.stringDeserializer.read(ns, toString(data));
        }
        if (traits.httpPayload) {
          if (ns.isBlobSchema()) {
            const toBytes = this.serdeContext?.utf8Decoder ?? fromUtf8;
            if (typeof data === "string") {
              return toBytes(data);
            }
            return data;
          } else if (ns.isStringSchema()) {
            if ("byteLength" in data) {
              return toString(data);
            }
            return data;
          }
        }
        return this.codecDeserializer.read(ns, data);
      }
    };
  }
});

// node_modules/@smithy/core/dist-es/submodules/protocols/serde/ToStringShapeSerializer.js
var ToStringShapeSerializer;
var init_ToStringShapeSerializer = __esm({
  "node_modules/@smithy/core/dist-es/submodules/protocols/serde/ToStringShapeSerializer.js"() {
    init_schema2();
    init_serde2();
    init_dist_es11();
    init_SerdeContext();
    init_determineTimestampFormat();
    ToStringShapeSerializer = class extends SerdeContext {
      settings;
      stringBuffer = "";
      constructor(settings) {
        super();
        this.settings = settings;
      }
      write(schema, value) {
        const ns = NormalizedSchema.of(schema);
        switch (typeof value) {
          case "object":
            if (value === null) {
              this.stringBuffer = "null";
              return;
            }
            if (ns.isTimestampSchema()) {
              if (!(value instanceof Date)) {
                throw new Error(`@smithy/core/protocols - received non-Date value ${value} when schema expected Date in ${ns.getName(true)}`);
              }
              const format2 = determineTimestampFormat(ns, this.settings);
              switch (format2) {
                case 5:
                  this.stringBuffer = value.toISOString().replace(".000Z", "Z");
                  break;
                case 6:
                  this.stringBuffer = dateToUtcString(value);
                  break;
                case 7:
                  this.stringBuffer = String(value.getTime() / 1e3);
                  break;
                default:
                  console.warn("Missing timestamp format, using epoch seconds", value);
                  this.stringBuffer = String(value.getTime() / 1e3);
              }
              return;
            }
            if (ns.isBlobSchema() && "byteLength" in value) {
              this.stringBuffer = (this.serdeContext?.base64Encoder ?? toBase64)(value);
              return;
            }
            if (ns.isListSchema() && Array.isArray(value)) {
              let buffer = "";
              for (const item of value) {
                this.write([ns.getValueSchema(), ns.getMergedTraits()], item);
                const headerItem = this.flush();
                const serialized = ns.getValueSchema().isTimestampSchema() ? headerItem : quoteHeader(headerItem);
                if (buffer !== "") {
                  buffer += ", ";
                }
                buffer += serialized;
              }
              this.stringBuffer = buffer;
              return;
            }
            this.stringBuffer = JSON.stringify(value, null, 2);
            break;
          case "string":
            const mediaType = ns.getMergedTraits().mediaType;
            let intermediateValue = value;
            if (mediaType) {
              const isJson = mediaType === "application/json" || mediaType.endsWith("+json");
              if (isJson) {
                intermediateValue = LazyJsonString.from(intermediateValue);
              }
              if (ns.getMergedTraits().httpHeader) {
                this.stringBuffer = (this.serdeContext?.base64Encoder ?? toBase64)(intermediateValue.toString());
                return;
              }
            }
            this.stringBuffer = value;
            break;
          default:
            if (ns.isIdempotencyToken()) {
              this.stringBuffer = v4();
            } else {
              this.stringBuffer = String(value);
            }
        }
      }
      flush() {
        const buffer = this.stringBuffer;
        this.stringBuffer = "";
        return buffer;
      }
    };
  }
});

// node_modules/@smithy/core/dist-es/submodules/protocols/serde/HttpInterceptingShapeSerializer.js
var HttpInterceptingShapeSerializer;
var init_HttpInterceptingShapeSerializer = __esm({
  "node_modules/@smithy/core/dist-es/submodules/protocols/serde/HttpInterceptingShapeSerializer.js"() {
    init_schema2();
    init_ToStringShapeSerializer();
    HttpInterceptingShapeSerializer = class {
      codecSerializer;
      stringSerializer;
      buffer;
      constructor(codecSerializer, codecSettings, stringSerializer = new ToStringShapeSerializer(codecSettings)) {
        this.codecSerializer = codecSerializer;
        this.stringSerializer = stringSerializer;
      }
      setSerdeContext(serdeContext) {
        this.codecSerializer.setSerdeContext(serdeContext);
        this.stringSerializer.setSerdeContext(serdeContext);
      }
      write(schema, value) {
        const ns = NormalizedSchema.of(schema);
        const traits = ns.getMergedTraits();
        if (traits.httpHeader || traits.httpLabel || traits.httpQuery) {
          this.stringSerializer.write(ns, value);
          this.buffer = this.stringSerializer.flush();
          return;
        }
        return this.codecSerializer.write(ns, value);
      }
      flush() {
        if (this.buffer !== void 0) {
          const buffer = this.buffer;
          this.buffer = void 0;
          return buffer;
        }
        return this.codecSerializer.flush();
      }
    };
  }
});

// node_modules/@smithy/core/dist-es/submodules/protocols/index.js
var init_protocols = __esm({
  "node_modules/@smithy/core/dist-es/submodules/protocols/index.js"() {
    init_collect_stream_body();
    init_extended_encode_uri_component();
    init_HttpBindingProtocol();
    init_HttpProtocol();
    init_RpcProtocol();
    init_requestBuilder();
    init_resolve_path();
    init_FromStringShapeDeserializer();
    init_HttpInterceptingShapeDeserializer();
    init_HttpInterceptingShapeSerializer();
    init_ToStringShapeSerializer();
    init_determineTimestampFormat();
    init_SerdeContext();
  }
});

// node_modules/@smithy/core/dist-es/request-builder/requestBuilder.js
var init_requestBuilder2 = __esm({
  "node_modules/@smithy/core/dist-es/request-builder/requestBuilder.js"() {
  }
});

// node_modules/@smithy/core/dist-es/setFeature.js
function setFeature(context, feature, value) {
  if (!context.__smithy_context) {
    context.__smithy_context = {
      features: {}
    };
  } else if (!context.__smithy_context.features) {
    context.__smithy_context.features = {};
  }
  context.__smithy_context.features[feature] = value;
}
var init_setFeature = __esm({
  "node_modules/@smithy/core/dist-es/setFeature.js"() {
  }
});

// node_modules/@smithy/core/dist-es/util-identity-and-auth/DefaultIdentityProviderConfig.js
var DefaultIdentityProviderConfig;
var init_DefaultIdentityProviderConfig = __esm({
  "node_modules/@smithy/core/dist-es/util-identity-and-auth/DefaultIdentityProviderConfig.js"() {
    DefaultIdentityProviderConfig = class {
      authSchemes = /* @__PURE__ */ new Map();
      constructor(config) {
        for (const [key, value] of Object.entries(config)) {
          if (value !== void 0) {
            this.authSchemes.set(key, value);
          }
        }
      }
      getIdentityProvider(schemeId) {
        return this.authSchemes.get(schemeId);
      }
    };
  }
});

// node_modules/@smithy/core/dist-es/util-identity-and-auth/httpAuthSchemes/httpApiKeyAuth.js
var init_httpApiKeyAuth = __esm({
  "node_modules/@smithy/core/dist-es/util-identity-and-auth/httpAuthSchemes/httpApiKeyAuth.js"() {
  }
});

// node_modules/@smithy/core/dist-es/util-identity-and-auth/httpAuthSchemes/httpBearerAuth.js
var init_httpBearerAuth = __esm({
  "node_modules/@smithy/core/dist-es/util-identity-and-auth/httpAuthSchemes/httpBearerAuth.js"() {
  }
});

// node_modules/@smithy/core/dist-es/util-identity-and-auth/httpAuthSchemes/noAuth.js
var NoAuthSigner;
var init_noAuth = __esm({
  "node_modules/@smithy/core/dist-es/util-identity-and-auth/httpAuthSchemes/noAuth.js"() {
    NoAuthSigner = class {
      async sign(httpRequest2, identity, signingProperties) {
        return httpRequest2;
      }
    };
  }
});

// node_modules/@smithy/core/dist-es/util-identity-and-auth/httpAuthSchemes/index.js
var init_httpAuthSchemes = __esm({
  "node_modules/@smithy/core/dist-es/util-identity-and-auth/httpAuthSchemes/index.js"() {
    init_httpApiKeyAuth();
    init_httpBearerAuth();
    init_noAuth();
  }
});

// node_modules/@smithy/core/dist-es/util-identity-and-auth/memoizeIdentityProvider.js
var createIsIdentityExpiredFunction, EXPIRATION_MS, isIdentityExpired, doesIdentityRequireRefresh, memoizeIdentityProvider;
var init_memoizeIdentityProvider = __esm({
  "node_modules/@smithy/core/dist-es/util-identity-and-auth/memoizeIdentityProvider.js"() {
    createIsIdentityExpiredFunction = (expirationMs) => function isIdentityExpired2(identity) {
      return doesIdentityRequireRefresh(identity) && identity.expiration.getTime() - Date.now() < expirationMs;
    };
    EXPIRATION_MS = 3e5;
    isIdentityExpired = createIsIdentityExpiredFunction(EXPIRATION_MS);
    doesIdentityRequireRefresh = (identity) => identity.expiration !== void 0;
    memoizeIdentityProvider = (provider, isExpired, requiresRefresh) => {
      if (provider === void 0) {
        return void 0;
      }
      const normalizedProvider = typeof provider !== "function" ? async () => Promise.resolve(provider) : provider;
      let resolved;
      let pending;
      let hasResult;
      let isConstant = false;
      const coalesceProvider = async (options) => {
        if (!pending) {
          pending = normalizedProvider(options);
        }
        try {
          resolved = await pending;
          hasResult = true;
          isConstant = false;
        } finally {
          pending = void 0;
        }
        return resolved;
      };
      if (isExpired === void 0) {
        return async (options) => {
          if (!hasResult || options?.forceRefresh) {
            resolved = await coalesceProvider(options);
          }
          return resolved;
        };
      }
      return async (options) => {
        if (!hasResult || options?.forceRefresh) {
          resolved = await coalesceProvider(options);
        }
        if (isConstant) {
          return resolved;
        }
        if (!requiresRefresh(resolved)) {
          isConstant = true;
          return resolved;
        }
        if (isExpired(resolved)) {
          await coalesceProvider(options);
          return resolved;
        }
        return resolved;
      };
    };
  }
});

// node_modules/@smithy/core/dist-es/util-identity-and-auth/index.js
var init_util_identity_and_auth = __esm({
  "node_modules/@smithy/core/dist-es/util-identity-and-auth/index.js"() {
    init_DefaultIdentityProviderConfig();
    init_httpAuthSchemes();
    init_memoizeIdentityProvider();
  }
});

// node_modules/@smithy/core/dist-es/index.js
var init_dist_es19 = __esm({
  "node_modules/@smithy/core/dist-es/index.js"() {
    init_getSmithyContext();
    init_middleware_http_auth_scheme();
    init_middleware_http_signing();
    init_normalizeProvider2();
    init_createPaginator();
    init_requestBuilder2();
    init_setFeature();
    init_util_identity_and_auth();
  }
});

// node_modules/@aws-sdk/middleware-user-agent/dist-es/configurations.js
function isValidUserAgentAppId(appId) {
  if (appId === void 0) {
    return true;
  }
  return typeof appId === "string" && appId.length <= 50;
}
function resolveUserAgentConfig(input) {
  const normalizedAppIdProvider = normalizeProvider2(input.userAgentAppId ?? DEFAULT_UA_APP_ID);
  const { customUserAgent } = input;
  return Object.assign(input, {
    customUserAgent: typeof customUserAgent === "string" ? [[customUserAgent]] : customUserAgent,
    userAgentAppId: async () => {
      const appId = await normalizedAppIdProvider();
      if (!isValidUserAgentAppId(appId)) {
        const logger2 = input.logger?.constructor?.name === "NoOpLogger" || !input.logger ? console : input.logger;
        if (typeof appId !== "string") {
          logger2?.warn("userAgentAppId must be a string or undefined.");
        } else if (appId.length > 50) {
          logger2?.warn("The provided userAgentAppId exceeds the maximum length of 50 characters.");
        }
      }
      return appId;
    }
  });
}
var DEFAULT_UA_APP_ID;
var init_configurations = __esm({
  "node_modules/@aws-sdk/middleware-user-agent/dist-es/configurations.js"() {
    init_dist_es19();
    DEFAULT_UA_APP_ID = void 0;
  }
});

// node_modules/@smithy/util-endpoints/dist-es/cache/EndpointCache.js
var EndpointCache;
var init_EndpointCache = __esm({
  "node_modules/@smithy/util-endpoints/dist-es/cache/EndpointCache.js"() {
    EndpointCache = class {
      capacity;
      data = /* @__PURE__ */ new Map();
      parameters = [];
      constructor({ size, params }) {
        this.capacity = size ?? 50;
        if (params) {
          this.parameters = params;
        }
      }
      get(endpointParams, resolver) {
        const key = this.hash(endpointParams);
        if (key === false) {
          return resolver();
        }
        if (!this.data.has(key)) {
          if (this.data.size > this.capacity + 10) {
            const keys = this.data.keys();
            let i6 = 0;
            while (true) {
              const { value, done } = keys.next();
              this.data.delete(value);
              if (done || ++i6 > 10) {
                break;
              }
            }
          }
          this.data.set(key, resolver());
        }
        return this.data.get(key);
      }
      size() {
        return this.data.size;
      }
      hash(endpointParams) {
        let buffer = "";
        const { parameters } = this;
        if (parameters.length === 0) {
          return false;
        }
        for (const param of parameters) {
          const val = String(endpointParams[param] ?? "");
          if (val.includes("|;")) {
            return false;
          }
          buffer += val + "|;";
        }
        return buffer;
      }
    };
  }
});

// node_modules/@smithy/util-endpoints/dist-es/lib/isIpAddress.js
var IP_V4_REGEX, isIpAddress;
var init_isIpAddress = __esm({
  "node_modules/@smithy/util-endpoints/dist-es/lib/isIpAddress.js"() {
    IP_V4_REGEX = new RegExp(`^(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]\\d|\\d)(?:\\.(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]\\d|\\d)){3}$`);
    isIpAddress = (value) => IP_V4_REGEX.test(value) || value.startsWith("[") && value.endsWith("]");
  }
});

// node_modules/@smithy/util-endpoints/dist-es/lib/isValidHostLabel.js
var VALID_HOST_LABEL_REGEX, isValidHostLabel;
var init_isValidHostLabel = __esm({
  "node_modules/@smithy/util-endpoints/dist-es/lib/isValidHostLabel.js"() {
    VALID_HOST_LABEL_REGEX = new RegExp(`^(?!.*-$)(?!-)[a-zA-Z0-9-]{1,63}$`);
    isValidHostLabel = (value, allowSubDomains = false) => {
      if (!allowSubDomains) {
        return VALID_HOST_LABEL_REGEX.test(value);
      }
      const labels = value.split(".");
      for (const label of labels) {
        if (!isValidHostLabel(label)) {
          return false;
        }
      }
      return true;
    };
  }
});

// node_modules/@smithy/util-endpoints/dist-es/utils/customEndpointFunctions.js
var customEndpointFunctions;
var init_customEndpointFunctions = __esm({
  "node_modules/@smithy/util-endpoints/dist-es/utils/customEndpointFunctions.js"() {
    customEndpointFunctions = {};
  }
});

// node_modules/@smithy/util-endpoints/dist-es/debug/debugId.js
var debugId;
var init_debugId = __esm({
  "node_modules/@smithy/util-endpoints/dist-es/debug/debugId.js"() {
    debugId = "endpoints";
  }
});

// node_modules/@smithy/util-endpoints/dist-es/debug/toDebugString.js
function toDebugString(input) {
  if (typeof input !== "object" || input == null) {
    return input;
  }
  if ("ref" in input) {
    return `$${toDebugString(input.ref)}`;
  }
  if ("fn" in input) {
    return `${input.fn}(${(input.argv || []).map(toDebugString).join(", ")})`;
  }
  return JSON.stringify(input, null, 2);
}
var init_toDebugString = __esm({
  "node_modules/@smithy/util-endpoints/dist-es/debug/toDebugString.js"() {
  }
});

// node_modules/@smithy/util-endpoints/dist-es/debug/index.js
var init_debug = __esm({
  "node_modules/@smithy/util-endpoints/dist-es/debug/index.js"() {
    init_debugId();
    init_toDebugString();
  }
});

// node_modules/@smithy/util-endpoints/dist-es/types/EndpointError.js
var EndpointError;
var init_EndpointError = __esm({
  "node_modules/@smithy/util-endpoints/dist-es/types/EndpointError.js"() {
    EndpointError = class extends Error {
      constructor(message) {
        super(message);
        this.name = "EndpointError";
      }
    };
  }
});

// node_modules/@smithy/util-endpoints/dist-es/types/EndpointFunctions.js
var init_EndpointFunctions = __esm({
  "node_modules/@smithy/util-endpoints/dist-es/types/EndpointFunctions.js"() {
  }
});

// node_modules/@smithy/util-endpoints/dist-es/types/EndpointRuleObject.js
var init_EndpointRuleObject2 = __esm({
  "node_modules/@smithy/util-endpoints/dist-es/types/EndpointRuleObject.js"() {
  }
});

// node_modules/@smithy/util-endpoints/dist-es/types/ErrorRuleObject.js
var init_ErrorRuleObject2 = __esm({
  "node_modules/@smithy/util-endpoints/dist-es/types/ErrorRuleObject.js"() {
  }
});

// node_modules/@smithy/util-endpoints/dist-es/types/RuleSetObject.js
var init_RuleSetObject2 = __esm({
  "node_modules/@smithy/util-endpoints/dist-es/types/RuleSetObject.js"() {
  }
});

// node_modules/@smithy/util-endpoints/dist-es/types/TreeRuleObject.js
var init_TreeRuleObject2 = __esm({
  "node_modules/@smithy/util-endpoints/dist-es/types/TreeRuleObject.js"() {
  }
});

// node_modules/@smithy/util-endpoints/dist-es/types/shared.js
var init_shared2 = __esm({
  "node_modules/@smithy/util-endpoints/dist-es/types/shared.js"() {
  }
});

// node_modules/@smithy/util-endpoints/dist-es/types/index.js
var init_types2 = __esm({
  "node_modules/@smithy/util-endpoints/dist-es/types/index.js"() {
    init_EndpointError();
    init_EndpointFunctions();
    init_EndpointRuleObject2();
    init_ErrorRuleObject2();
    init_RuleSetObject2();
    init_TreeRuleObject2();
    init_shared2();
  }
});

// node_modules/@smithy/util-endpoints/dist-es/lib/booleanEquals.js
var booleanEquals;
var init_booleanEquals = __esm({
  "node_modules/@smithy/util-endpoints/dist-es/lib/booleanEquals.js"() {
    booleanEquals = (value1, value2) => value1 === value2;
  }
});

// node_modules/@smithy/util-endpoints/dist-es/lib/getAttrPathList.js
var getAttrPathList;
var init_getAttrPathList = __esm({
  "node_modules/@smithy/util-endpoints/dist-es/lib/getAttrPathList.js"() {
    init_types2();
    getAttrPathList = (path) => {
      const parts = path.split(".");
      const pathList = [];
      for (const part of parts) {
        const squareBracketIndex = part.indexOf("[");
        if (squareBracketIndex !== -1) {
          if (part.indexOf("]") !== part.length - 1) {
            throw new EndpointError(`Path: '${path}' does not end with ']'`);
          }
          const arrayIndex = part.slice(squareBracketIndex + 1, -1);
          if (Number.isNaN(parseInt(arrayIndex))) {
            throw new EndpointError(`Invalid array index: '${arrayIndex}' in path: '${path}'`);
          }
          if (squareBracketIndex !== 0) {
            pathList.push(part.slice(0, squareBracketIndex));
          }
          pathList.push(arrayIndex);
        } else {
          pathList.push(part);
        }
      }
      return pathList;
    };
  }
});

// node_modules/@smithy/util-endpoints/dist-es/lib/getAttr.js
var getAttr;
var init_getAttr = __esm({
  "node_modules/@smithy/util-endpoints/dist-es/lib/getAttr.js"() {
    init_types2();
    init_getAttrPathList();
    getAttr = (value, path) => getAttrPathList(path).reduce((acc, index) => {
      if (typeof acc !== "object") {
        throw new EndpointError(`Index '${index}' in '${path}' not found in '${JSON.stringify(value)}'`);
      } else if (Array.isArray(acc)) {
        return acc[parseInt(index)];
      }
      return acc[index];
    }, value);
  }
});

// node_modules/@smithy/util-endpoints/dist-es/lib/isSet.js
var isSet;
var init_isSet = __esm({
  "node_modules/@smithy/util-endpoints/dist-es/lib/isSet.js"() {
    isSet = (value) => value != null;
  }
});

// node_modules/@smithy/util-endpoints/dist-es/lib/not.js
var not;
var init_not = __esm({
  "node_modules/@smithy/util-endpoints/dist-es/lib/not.js"() {
    not = (value) => !value;
  }
});

// node_modules/@smithy/util-endpoints/dist-es/lib/parseURL.js
var DEFAULT_PORTS, parseURL;
var init_parseURL = __esm({
  "node_modules/@smithy/util-endpoints/dist-es/lib/parseURL.js"() {
    init_dist_es();
    init_isIpAddress();
    DEFAULT_PORTS = {
      [EndpointURLScheme.HTTP]: 80,
      [EndpointURLScheme.HTTPS]: 443
    };
    parseURL = (value) => {
      const whatwgURL = (() => {
        try {
          if (value instanceof URL) {
            return value;
          }
          if (typeof value === "object" && "hostname" in value) {
            const { hostname: hostname2, port, protocol: protocol2 = "", path = "", query = {} } = value;
            const url = new URL(`${protocol2}//${hostname2}${port ? `:${port}` : ""}${path}`);
            url.search = Object.entries(query).map(([k6, v7]) => `${k6}=${v7}`).join("&");
            return url;
          }
          return new URL(value);
        } catch (error) {
          return null;
        }
      })();
      if (!whatwgURL) {
        console.error(`Unable to parse ${JSON.stringify(value)} as a whatwg URL.`);
        return null;
      }
      const urlString = whatwgURL.href;
      const { host, hostname, pathname, protocol, search } = whatwgURL;
      if (search) {
        return null;
      }
      const scheme = protocol.slice(0, -1);
      if (!Object.values(EndpointURLScheme).includes(scheme)) {
        return null;
      }
      const isIp = isIpAddress(hostname);
      const inputContainsDefaultPort = urlString.includes(`${host}:${DEFAULT_PORTS[scheme]}`) || typeof value === "string" && value.includes(`${host}:${DEFAULT_PORTS[scheme]}`);
      const authority = `${host}${inputContainsDefaultPort ? `:${DEFAULT_PORTS[scheme]}` : ``}`;
      return {
        scheme,
        authority,
        path: pathname,
        normalizedPath: pathname.endsWith("/") ? pathname : `${pathname}/`,
        isIp
      };
    };
  }
});

// node_modules/@smithy/util-endpoints/dist-es/lib/stringEquals.js
var stringEquals;
var init_stringEquals = __esm({
  "node_modules/@smithy/util-endpoints/dist-es/lib/stringEquals.js"() {
    stringEquals = (value1, value2) => value1 === value2;
  }
});

// node_modules/@smithy/util-endpoints/dist-es/lib/substring.js
var substring;
var init_substring = __esm({
  "node_modules/@smithy/util-endpoints/dist-es/lib/substring.js"() {
    substring = (input, start, stop, reverse) => {
      if (start >= stop || input.length < stop) {
        return null;
      }
      if (!reverse) {
        return input.substring(start, stop);
      }
      return input.substring(input.length - stop, input.length - start);
    };
  }
});

// node_modules/@smithy/util-endpoints/dist-es/lib/uriEncode.js
var uriEncode;
var init_uriEncode = __esm({
  "node_modules/@smithy/util-endpoints/dist-es/lib/uriEncode.js"() {
    uriEncode = (value) => encodeURIComponent(value).replace(/[!*'()]/g, (c6) => `%${c6.charCodeAt(0).toString(16).toUpperCase()}`);
  }
});

// node_modules/@smithy/util-endpoints/dist-es/lib/index.js
var init_lib = __esm({
  "node_modules/@smithy/util-endpoints/dist-es/lib/index.js"() {
    init_booleanEquals();
    init_getAttr();
    init_isSet();
    init_isValidHostLabel();
    init_not();
    init_parseURL();
    init_stringEquals();
    init_substring();
    init_uriEncode();
  }
});

// node_modules/@smithy/util-endpoints/dist-es/utils/endpointFunctions.js
var endpointFunctions;
var init_endpointFunctions = __esm({
  "node_modules/@smithy/util-endpoints/dist-es/utils/endpointFunctions.js"() {
    init_lib();
    endpointFunctions = {
      booleanEquals,
      getAttr,
      isSet,
      isValidHostLabel,
      not,
      parseURL,
      stringEquals,
      substring,
      uriEncode
    };
  }
});

// node_modules/@smithy/util-endpoints/dist-es/utils/evaluateTemplate.js
var evaluateTemplate;
var init_evaluateTemplate = __esm({
  "node_modules/@smithy/util-endpoints/dist-es/utils/evaluateTemplate.js"() {
    init_lib();
    evaluateTemplate = (template, options) => {
      const evaluatedTemplateArr = [];
      const templateContext = {
        ...options.endpointParams,
        ...options.referenceRecord
      };
      let currentIndex = 0;
      while (currentIndex < template.length) {
        const openingBraceIndex = template.indexOf("{", currentIndex);
        if (openingBraceIndex === -1) {
          evaluatedTemplateArr.push(template.slice(currentIndex));
          break;
        }
        evaluatedTemplateArr.push(template.slice(currentIndex, openingBraceIndex));
        const closingBraceIndex = template.indexOf("}", openingBraceIndex);
        if (closingBraceIndex === -1) {
          evaluatedTemplateArr.push(template.slice(openingBraceIndex));
          break;
        }
        if (template[openingBraceIndex + 1] === "{" && template[closingBraceIndex + 1] === "}") {
          evaluatedTemplateArr.push(template.slice(openingBraceIndex + 1, closingBraceIndex));
          currentIndex = closingBraceIndex + 2;
        }
        const parameterName = template.substring(openingBraceIndex + 1, closingBraceIndex);
        if (parameterName.includes("#")) {
          const [refName, attrName] = parameterName.split("#");
          evaluatedTemplateArr.push(getAttr(templateContext[refName], attrName));
        } else {
          evaluatedTemplateArr.push(templateContext[parameterName]);
        }
        currentIndex = closingBraceIndex + 1;
      }
      return evaluatedTemplateArr.join("");
    };
  }
});

// node_modules/@smithy/util-endpoints/dist-es/utils/getReferenceValue.js
var getReferenceValue;
var init_getReferenceValue = __esm({
  "node_modules/@smithy/util-endpoints/dist-es/utils/getReferenceValue.js"() {
    getReferenceValue = ({ ref }, options) => {
      const referenceRecord = {
        ...options.endpointParams,
        ...options.referenceRecord
      };
      return referenceRecord[ref];
    };
  }
});

// node_modules/@smithy/util-endpoints/dist-es/utils/evaluateExpression.js
var evaluateExpression, callFunction, group;
var init_evaluateExpression = __esm({
  "node_modules/@smithy/util-endpoints/dist-es/utils/evaluateExpression.js"() {
    init_types2();
    init_customEndpointFunctions();
    init_endpointFunctions();
    init_evaluateTemplate();
    init_getReferenceValue();
    evaluateExpression = (obj, keyName, options) => {
      if (typeof obj === "string") {
        return evaluateTemplate(obj, options);
      } else if (obj["fn"]) {
        return group.callFunction(obj, options);
      } else if (obj["ref"]) {
        return getReferenceValue(obj, options);
      }
      throw new EndpointError(`'${keyName}': ${String(obj)} is not a string, function or reference.`);
    };
    callFunction = ({ fn, argv }, options) => {
      const evaluatedArgs = argv.map((arg) => ["boolean", "number"].includes(typeof arg) ? arg : group.evaluateExpression(arg, "arg", options));
      const fnSegments = fn.split(".");
      if (fnSegments[0] in customEndpointFunctions && fnSegments[1] != null) {
        return customEndpointFunctions[fnSegments[0]][fnSegments[1]](...evaluatedArgs);
      }
      return endpointFunctions[fn](...evaluatedArgs);
    };
    group = {
      evaluateExpression,
      callFunction
    };
  }
});

// node_modules/@smithy/util-endpoints/dist-es/utils/callFunction.js
var init_callFunction = __esm({
  "node_modules/@smithy/util-endpoints/dist-es/utils/callFunction.js"() {
    init_evaluateExpression();
  }
});

// node_modules/@smithy/util-endpoints/dist-es/utils/evaluateCondition.js
var evaluateCondition;
var init_evaluateCondition = __esm({
  "node_modules/@smithy/util-endpoints/dist-es/utils/evaluateCondition.js"() {
    init_debug();
    init_types2();
    init_callFunction();
    evaluateCondition = ({ assign, ...fnArgs }, options) => {
      if (assign && assign in options.referenceRecord) {
        throw new EndpointError(`'${assign}' is already defined in Reference Record.`);
      }
      const value = callFunction(fnArgs, options);
      options.logger?.debug?.(`${debugId} evaluateCondition: ${toDebugString(fnArgs)} = ${toDebugString(value)}`);
      return {
        result: value === "" ? true : !!value,
        ...assign != null && { toAssign: { name: assign, value } }
      };
    };
  }
});

// node_modules/@smithy/util-endpoints/dist-es/utils/evaluateConditions.js
var evaluateConditions;
var init_evaluateConditions = __esm({
  "node_modules/@smithy/util-endpoints/dist-es/utils/evaluateConditions.js"() {
    init_debug();
    init_evaluateCondition();
    evaluateConditions = (conditions = [], options) => {
      const conditionsReferenceRecord = {};
      for (const condition of conditions) {
        const { result, toAssign } = evaluateCondition(condition, {
          ...options,
          referenceRecord: {
            ...options.referenceRecord,
            ...conditionsReferenceRecord
          }
        });
        if (!result) {
          return { result };
        }
        if (toAssign) {
          conditionsReferenceRecord[toAssign.name] = toAssign.value;
          options.logger?.debug?.(`${debugId} assign: ${toAssign.name} := ${toDebugString(toAssign.value)}`);
        }
      }
      return { result: true, referenceRecord: conditionsReferenceRecord };
    };
  }
});

// node_modules/@smithy/util-endpoints/dist-es/utils/getEndpointHeaders.js
var getEndpointHeaders;
var init_getEndpointHeaders = __esm({
  "node_modules/@smithy/util-endpoints/dist-es/utils/getEndpointHeaders.js"() {
    init_types2();
    init_evaluateExpression();
    getEndpointHeaders = (headers, options) => Object.entries(headers).reduce((acc, [headerKey, headerVal]) => ({
      ...acc,
      [headerKey]: headerVal.map((headerValEntry) => {
        const processedExpr = evaluateExpression(headerValEntry, "Header value entry", options);
        if (typeof processedExpr !== "string") {
          throw new EndpointError(`Header '${headerKey}' value '${processedExpr}' is not a string`);
        }
        return processedExpr;
      })
    }), {});
  }
});

// node_modules/@smithy/util-endpoints/dist-es/utils/getEndpointProperties.js
var getEndpointProperties, getEndpointProperty, group2;
var init_getEndpointProperties = __esm({
  "node_modules/@smithy/util-endpoints/dist-es/utils/getEndpointProperties.js"() {
    init_types2();
    init_evaluateTemplate();
    getEndpointProperties = (properties, options) => Object.entries(properties).reduce((acc, [propertyKey, propertyVal]) => ({
      ...acc,
      [propertyKey]: group2.getEndpointProperty(propertyVal, options)
    }), {});
    getEndpointProperty = (property, options) => {
      if (Array.isArray(property)) {
        return property.map((propertyEntry) => getEndpointProperty(propertyEntry, options));
      }
      switch (typeof property) {
        case "string":
          return evaluateTemplate(property, options);
        case "object":
          if (property === null) {
            throw new EndpointError(`Unexpected endpoint property: ${property}`);
          }
          return group2.getEndpointProperties(property, options);
        case "boolean":
          return property;
        default:
          throw new EndpointError(`Unexpected endpoint property type: ${typeof property}`);
      }
    };
    group2 = {
      getEndpointProperty,
      getEndpointProperties
    };
  }
});

// node_modules/@smithy/util-endpoints/dist-es/utils/getEndpointUrl.js
var getEndpointUrl;
var init_getEndpointUrl = __esm({
  "node_modules/@smithy/util-endpoints/dist-es/utils/getEndpointUrl.js"() {
    init_types2();
    init_evaluateExpression();
    getEndpointUrl = (endpointUrl, options) => {
      const expression = evaluateExpression(endpointUrl, "Endpoint URL", options);
      if (typeof expression === "string") {
        try {
          return new URL(expression);
        } catch (error) {
          console.error(`Failed to construct URL with ${expression}`, error);
          throw error;
        }
      }
      throw new EndpointError(`Endpoint URL must be a string, got ${typeof expression}`);
    };
  }
});

// node_modules/@smithy/util-endpoints/dist-es/utils/evaluateEndpointRule.js
var evaluateEndpointRule;
var init_evaluateEndpointRule = __esm({
  "node_modules/@smithy/util-endpoints/dist-es/utils/evaluateEndpointRule.js"() {
    init_debug();
    init_evaluateConditions();
    init_getEndpointHeaders();
    init_getEndpointProperties();
    init_getEndpointUrl();
    evaluateEndpointRule = (endpointRule, options) => {
      const { conditions, endpoint } = endpointRule;
      const { result, referenceRecord } = evaluateConditions(conditions, options);
      if (!result) {
        return;
      }
      const endpointRuleOptions = {
        ...options,
        referenceRecord: { ...options.referenceRecord, ...referenceRecord }
      };
      const { url, properties, headers } = endpoint;
      options.logger?.debug?.(`${debugId} Resolving endpoint from template: ${toDebugString(endpoint)}`);
      return {
        ...headers != void 0 && {
          headers: getEndpointHeaders(headers, endpointRuleOptions)
        },
        ...properties != void 0 && {
          properties: getEndpointProperties(properties, endpointRuleOptions)
        },
        url: getEndpointUrl(url, endpointRuleOptions)
      };
    };
  }
});

// node_modules/@smithy/util-endpoints/dist-es/utils/evaluateErrorRule.js
var evaluateErrorRule;
var init_evaluateErrorRule = __esm({
  "node_modules/@smithy/util-endpoints/dist-es/utils/evaluateErrorRule.js"() {
    init_types2();
    init_evaluateConditions();
    init_evaluateExpression();
    evaluateErrorRule = (errorRule, options) => {
      const { conditions, error } = errorRule;
      const { result, referenceRecord } = evaluateConditions(conditions, options);
      if (!result) {
        return;
      }
      throw new EndpointError(evaluateExpression(error, "Error", {
        ...options,
        referenceRecord: { ...options.referenceRecord, ...referenceRecord }
      }));
    };
  }
});

// node_modules/@smithy/util-endpoints/dist-es/utils/evaluateRules.js
var evaluateRules, evaluateTreeRule, group3;
var init_evaluateRules = __esm({
  "node_modules/@smithy/util-endpoints/dist-es/utils/evaluateRules.js"() {
    init_types2();
    init_evaluateConditions();
    init_evaluateEndpointRule();
    init_evaluateErrorRule();
    evaluateRules = (rules, options) => {
      for (const rule of rules) {
        if (rule.type === "endpoint") {
          const endpointOrUndefined = evaluateEndpointRule(rule, options);
          if (endpointOrUndefined) {
            return endpointOrUndefined;
          }
        } else if (rule.type === "error") {
          evaluateErrorRule(rule, options);
        } else if (rule.type === "tree") {
          const endpointOrUndefined = group3.evaluateTreeRule(rule, options);
          if (endpointOrUndefined) {
            return endpointOrUndefined;
          }
        } else {
          throw new EndpointError(`Unknown endpoint rule: ${rule}`);
        }
      }
      throw new EndpointError(`Rules evaluation failed`);
    };
    evaluateTreeRule = (treeRule, options) => {
      const { conditions, rules } = treeRule;
      const { result, referenceRecord } = evaluateConditions(conditions, options);
      if (!result) {
        return;
      }
      return group3.evaluateRules(rules, {
        ...options,
        referenceRecord: { ...options.referenceRecord, ...referenceRecord }
      });
    };
    group3 = {
      evaluateRules,
      evaluateTreeRule
    };
  }
});

// node_modules/@smithy/util-endpoints/dist-es/utils/index.js
var init_utils = __esm({
  "node_modules/@smithy/util-endpoints/dist-es/utils/index.js"() {
    init_customEndpointFunctions();
    init_evaluateRules();
  }
});

// node_modules/@smithy/util-endpoints/dist-es/resolveEndpoint.js
var resolveEndpoint;
var init_resolveEndpoint = __esm({
  "node_modules/@smithy/util-endpoints/dist-es/resolveEndpoint.js"() {
    init_debug();
    init_types2();
    init_utils();
    resolveEndpoint = (ruleSetObject, options) => {
      const { endpointParams, logger: logger2 } = options;
      const { parameters, rules } = ruleSetObject;
      options.logger?.debug?.(`${debugId} Initial EndpointParams: ${toDebugString(endpointParams)}`);
      const paramsWithDefault = Object.entries(parameters).filter(([, v7]) => v7.default != null).map(([k6, v7]) => [k6, v7.default]);
      if (paramsWithDefault.length > 0) {
        for (const [paramKey, paramDefaultValue] of paramsWithDefault) {
          endpointParams[paramKey] = endpointParams[paramKey] ?? paramDefaultValue;
        }
      }
      const requiredParams = Object.entries(parameters).filter(([, v7]) => v7.required).map(([k6]) => k6);
      for (const requiredParam of requiredParams) {
        if (endpointParams[requiredParam] == null) {
          throw new EndpointError(`Missing required parameter: '${requiredParam}'`);
        }
      }
      const endpoint = evaluateRules(rules, { endpointParams, logger: logger2, referenceRecord: {} });
      options.logger?.debug?.(`${debugId} Resolved endpoint: ${toDebugString(endpoint)}`);
      return endpoint;
    };
  }
});

// node_modules/@smithy/util-endpoints/dist-es/index.js
var init_dist_es20 = __esm({
  "node_modules/@smithy/util-endpoints/dist-es/index.js"() {
    init_EndpointCache();
    init_isIpAddress();
    init_isValidHostLabel();
    init_customEndpointFunctions();
    init_resolveEndpoint();
    init_types2();
  }
});

// node_modules/@aws-sdk/util-endpoints/dist-es/lib/isIpAddress.js
var init_isIpAddress2 = __esm({
  "node_modules/@aws-sdk/util-endpoints/dist-es/lib/isIpAddress.js"() {
    init_dist_es20();
  }
});

// node_modules/@aws-sdk/util-endpoints/dist-es/lib/aws/isVirtualHostableS3Bucket.js
var isVirtualHostableS3Bucket;
var init_isVirtualHostableS3Bucket = __esm({
  "node_modules/@aws-sdk/util-endpoints/dist-es/lib/aws/isVirtualHostableS3Bucket.js"() {
    init_dist_es20();
    init_isIpAddress2();
    isVirtualHostableS3Bucket = (value, allowSubDomains = false) => {
      if (allowSubDomains) {
        for (const label of value.split(".")) {
          if (!isVirtualHostableS3Bucket(label)) {
            return false;
          }
        }
        return true;
      }
      if (!isValidHostLabel(value)) {
        return false;
      }
      if (value.length < 3 || value.length > 63) {
        return false;
      }
      if (value !== value.toLowerCase()) {
        return false;
      }
      if (isIpAddress(value)) {
        return false;
      }
      return true;
    };
  }
});

// node_modules/@aws-sdk/util-endpoints/dist-es/lib/aws/parseArn.js
var ARN_DELIMITER, RESOURCE_DELIMITER, parseArn;
var init_parseArn = __esm({
  "node_modules/@aws-sdk/util-endpoints/dist-es/lib/aws/parseArn.js"() {
    ARN_DELIMITER = ":";
    RESOURCE_DELIMITER = "/";
    parseArn = (value) => {
      const segments = value.split(ARN_DELIMITER);
      if (segments.length < 6)
        return null;
      const [arn, partition2, service, region, accountId, ...resourcePath] = segments;
      if (arn !== "arn" || partition2 === "" || service === "" || resourcePath.join(ARN_DELIMITER) === "")
        return null;
      const resourceId = resourcePath.map((resource) => resource.split(RESOURCE_DELIMITER)).flat();
      return {
        partition: partition2,
        service,
        region,
        accountId,
        resourceId
      };
    };
  }
});

// node_modules/@aws-sdk/util-endpoints/dist-es/lib/aws/partitions.json
var partitions_default;
var init_partitions = __esm({
  "node_modules/@aws-sdk/util-endpoints/dist-es/lib/aws/partitions.json"() {
    partitions_default = {
      partitions: [{
        id: "aws",
        outputs: {
          dnsSuffix: "amazonaws.com",
          dualStackDnsSuffix: "api.aws",
          implicitGlobalRegion: "us-east-1",
          name: "aws",
          supportsDualStack: true,
          supportsFIPS: true
        },
        regionRegex: "^(us|eu|ap|sa|ca|me|af|il|mx)\\-\\w+\\-\\d+$",
        regions: {
          "af-south-1": {
            description: "Africa (Cape Town)"
          },
          "ap-east-1": {
            description: "Asia Pacific (Hong Kong)"
          },
          "ap-east-2": {
            description: "Asia Pacific (Taipei)"
          },
          "ap-northeast-1": {
            description: "Asia Pacific (Tokyo)"
          },
          "ap-northeast-2": {
            description: "Asia Pacific (Seoul)"
          },
          "ap-northeast-3": {
            description: "Asia Pacific (Osaka)"
          },
          "ap-south-1": {
            description: "Asia Pacific (Mumbai)"
          },
          "ap-south-2": {
            description: "Asia Pacific (Hyderabad)"
          },
          "ap-southeast-1": {
            description: "Asia Pacific (Singapore)"
          },
          "ap-southeast-2": {
            description: "Asia Pacific (Sydney)"
          },
          "ap-southeast-3": {
            description: "Asia Pacific (Jakarta)"
          },
          "ap-southeast-4": {
            description: "Asia Pacific (Melbourne)"
          },
          "ap-southeast-5": {
            description: "Asia Pacific (Malaysia)"
          },
          "ap-southeast-6": {
            description: "Asia Pacific (New Zealand)"
          },
          "ap-southeast-7": {
            description: "Asia Pacific (Thailand)"
          },
          "aws-global": {
            description: "aws global region"
          },
          "ca-central-1": {
            description: "Canada (Central)"
          },
          "ca-west-1": {
            description: "Canada West (Calgary)"
          },
          "eu-central-1": {
            description: "Europe (Frankfurt)"
          },
          "eu-central-2": {
            description: "Europe (Zurich)"
          },
          "eu-north-1": {
            description: "Europe (Stockholm)"
          },
          "eu-south-1": {
            description: "Europe (Milan)"
          },
          "eu-south-2": {
            description: "Europe (Spain)"
          },
          "eu-west-1": {
            description: "Europe (Ireland)"
          },
          "eu-west-2": {
            description: "Europe (London)"
          },
          "eu-west-3": {
            description: "Europe (Paris)"
          },
          "il-central-1": {
            description: "Israel (Tel Aviv)"
          },
          "me-central-1": {
            description: "Middle East (UAE)"
          },
          "me-south-1": {
            description: "Middle East (Bahrain)"
          },
          "mx-central-1": {
            description: "Mexico (Central)"
          },
          "sa-east-1": {
            description: "South America (Sao Paulo)"
          },
          "us-east-1": {
            description: "US East (N. Virginia)"
          },
          "us-east-2": {
            description: "US East (Ohio)"
          },
          "us-west-1": {
            description: "US West (N. California)"
          },
          "us-west-2": {
            description: "US West (Oregon)"
          }
        }
      }, {
        id: "aws-cn",
        outputs: {
          dnsSuffix: "amazonaws.com.cn",
          dualStackDnsSuffix: "api.amazonwebservices.com.cn",
          implicitGlobalRegion: "cn-northwest-1",
          name: "aws-cn",
          supportsDualStack: true,
          supportsFIPS: true
        },
        regionRegex: "^cn\\-\\w+\\-\\d+$",
        regions: {
          "aws-cn-global": {
            description: "aws-cn global region"
          },
          "cn-north-1": {
            description: "China (Beijing)"
          },
          "cn-northwest-1": {
            description: "China (Ningxia)"
          }
        }
      }, {
        id: "aws-eusc",
        outputs: {
          dnsSuffix: "amazonaws.eu",
          dualStackDnsSuffix: "api.amazonwebservices.eu",
          implicitGlobalRegion: "eusc-de-east-1",
          name: "aws-eusc",
          supportsDualStack: true,
          supportsFIPS: true
        },
        regionRegex: "^eusc\\-(de)\\-\\w+\\-\\d+$",
        regions: {
          "eusc-de-east-1": {
            description: "EU (Germany)"
          }
        }
      }, {
        id: "aws-iso",
        outputs: {
          dnsSuffix: "c2s.ic.gov",
          dualStackDnsSuffix: "api.aws.ic.gov",
          implicitGlobalRegion: "us-iso-east-1",
          name: "aws-iso",
          supportsDualStack: true,
          supportsFIPS: true
        },
        regionRegex: "^us\\-iso\\-\\w+\\-\\d+$",
        regions: {
          "aws-iso-global": {
            description: "aws-iso global region"
          },
          "us-iso-east-1": {
            description: "US ISO East"
          },
          "us-iso-west-1": {
            description: "US ISO WEST"
          }
        }
      }, {
        id: "aws-iso-b",
        outputs: {
          dnsSuffix: "sc2s.sgov.gov",
          dualStackDnsSuffix: "api.aws.scloud",
          implicitGlobalRegion: "us-isob-east-1",
          name: "aws-iso-b",
          supportsDualStack: true,
          supportsFIPS: true
        },
        regionRegex: "^us\\-isob\\-\\w+\\-\\d+$",
        regions: {
          "aws-iso-b-global": {
            description: "aws-iso-b global region"
          },
          "us-isob-east-1": {
            description: "US ISOB East (Ohio)"
          },
          "us-isob-west-1": {
            description: "US ISOB West"
          }
        }
      }, {
        id: "aws-iso-e",
        outputs: {
          dnsSuffix: "cloud.adc-e.uk",
          dualStackDnsSuffix: "api.cloud-aws.adc-e.uk",
          implicitGlobalRegion: "eu-isoe-west-1",
          name: "aws-iso-e",
          supportsDualStack: true,
          supportsFIPS: true
        },
        regionRegex: "^eu\\-isoe\\-\\w+\\-\\d+$",
        regions: {
          "aws-iso-e-global": {
            description: "aws-iso-e global region"
          },
          "eu-isoe-west-1": {
            description: "EU ISOE West"
          }
        }
      }, {
        id: "aws-iso-f",
        outputs: {
          dnsSuffix: "csp.hci.ic.gov",
          dualStackDnsSuffix: "api.aws.hci.ic.gov",
          implicitGlobalRegion: "us-isof-south-1",
          name: "aws-iso-f",
          supportsDualStack: true,
          supportsFIPS: true
        },
        regionRegex: "^us\\-isof\\-\\w+\\-\\d+$",
        regions: {
          "aws-iso-f-global": {
            description: "aws-iso-f global region"
          },
          "us-isof-east-1": {
            description: "US ISOF EAST"
          },
          "us-isof-south-1": {
            description: "US ISOF SOUTH"
          }
        }
      }, {
        id: "aws-us-gov",
        outputs: {
          dnsSuffix: "amazonaws.com",
          dualStackDnsSuffix: "api.aws",
          implicitGlobalRegion: "us-gov-west-1",
          name: "aws-us-gov",
          supportsDualStack: true,
          supportsFIPS: true
        },
        regionRegex: "^us\\-gov\\-\\w+\\-\\d+$",
        regions: {
          "aws-us-gov-global": {
            description: "aws-us-gov global region"
          },
          "us-gov-east-1": {
            description: "AWS GovCloud (US-East)"
          },
          "us-gov-west-1": {
            description: "AWS GovCloud (US-West)"
          }
        }
      }],
      version: "1.1"
    };
  }
});

// node_modules/@aws-sdk/util-endpoints/dist-es/lib/aws/partition.js
var selectedPartitionsInfo, selectedUserAgentPrefix, partition, getUserAgentPrefix;
var init_partition = __esm({
  "node_modules/@aws-sdk/util-endpoints/dist-es/lib/aws/partition.js"() {
    init_partitions();
    selectedPartitionsInfo = partitions_default;
    selectedUserAgentPrefix = "";
    partition = (value) => {
      const { partitions } = selectedPartitionsInfo;
      for (const partition2 of partitions) {
        const { regions, outputs } = partition2;
        for (const [region, regionData] of Object.entries(regions)) {
          if (region === value) {
            return {
              ...outputs,
              ...regionData
            };
          }
        }
      }
      for (const partition2 of partitions) {
        const { regionRegex, outputs } = partition2;
        if (new RegExp(regionRegex).test(value)) {
          return {
            ...outputs
          };
        }
      }
      const DEFAULT_PARTITION = partitions.find((partition2) => partition2.id === "aws");
      if (!DEFAULT_PARTITION) {
        throw new Error("Provided region was not found in the partition array or regex, and default partition with id 'aws' doesn't exist.");
      }
      return {
        ...DEFAULT_PARTITION.outputs
      };
    };
    getUserAgentPrefix = () => selectedUserAgentPrefix;
  }
});

// node_modules/@aws-sdk/util-endpoints/dist-es/aws.js
var awsEndpointFunctions;
var init_aws = __esm({
  "node_modules/@aws-sdk/util-endpoints/dist-es/aws.js"() {
    init_dist_es20();
    init_isVirtualHostableS3Bucket();
    init_parseArn();
    init_partition();
    awsEndpointFunctions = {
      isVirtualHostableS3Bucket,
      parseArn,
      partition
    };
    customEndpointFunctions.aws = awsEndpointFunctions;
  }
});

// node_modules/@smithy/querystring-parser/dist-es/index.js
function parseQueryString(querystring) {
  const query = {};
  querystring = querystring.replace(/^\?/, "");
  if (querystring) {
    for (const pair of querystring.split("&")) {
      let [key, value = null] = pair.split("=");
      key = decodeURIComponent(key);
      if (value) {
        value = decodeURIComponent(value);
      }
      if (!(key in query)) {
        query[key] = value;
      } else if (Array.isArray(query[key])) {
        query[key].push(value);
      } else {
        query[key] = [query[key], value];
      }
    }
  }
  return query;
}
var init_dist_es21 = __esm({
  "node_modules/@smithy/querystring-parser/dist-es/index.js"() {
  }
});

// node_modules/@smithy/url-parser/dist-es/index.js
var parseUrl;
var init_dist_es22 = __esm({
  "node_modules/@smithy/url-parser/dist-es/index.js"() {
    init_dist_es21();
    parseUrl = (url) => {
      if (typeof url === "string") {
        return parseUrl(new URL(url));
      }
      const { hostname, pathname, port, protocol, search } = url;
      let query;
      if (search) {
        query = parseQueryString(search);
      }
      return {
        hostname,
        port: port ? parseInt(port) : void 0,
        protocol,
        path: pathname,
        query
      };
    };
  }
});

// node_modules/@aws-sdk/util-endpoints/dist-es/resolveDefaultAwsRegionalEndpointsConfig.js
var init_resolveDefaultAwsRegionalEndpointsConfig = __esm({
  "node_modules/@aws-sdk/util-endpoints/dist-es/resolveDefaultAwsRegionalEndpointsConfig.js"() {
  }
});

// node_modules/@aws-sdk/util-endpoints/dist-es/resolveEndpoint.js
var init_resolveEndpoint2 = __esm({
  "node_modules/@aws-sdk/util-endpoints/dist-es/resolveEndpoint.js"() {
  }
});

// node_modules/@aws-sdk/util-endpoints/dist-es/types/EndpointError.js
var init_EndpointError2 = __esm({
  "node_modules/@aws-sdk/util-endpoints/dist-es/types/EndpointError.js"() {
  }
});

// node_modules/@aws-sdk/util-endpoints/dist-es/types/EndpointRuleObject.js
var init_EndpointRuleObject3 = __esm({
  "node_modules/@aws-sdk/util-endpoints/dist-es/types/EndpointRuleObject.js"() {
  }
});

// node_modules/@aws-sdk/util-endpoints/dist-es/types/ErrorRuleObject.js
var init_ErrorRuleObject3 = __esm({
  "node_modules/@aws-sdk/util-endpoints/dist-es/types/ErrorRuleObject.js"() {
  }
});

// node_modules/@aws-sdk/util-endpoints/dist-es/types/RuleSetObject.js
var init_RuleSetObject3 = __esm({
  "node_modules/@aws-sdk/util-endpoints/dist-es/types/RuleSetObject.js"() {
  }
});

// node_modules/@aws-sdk/util-endpoints/dist-es/types/TreeRuleObject.js
var init_TreeRuleObject3 = __esm({
  "node_modules/@aws-sdk/util-endpoints/dist-es/types/TreeRuleObject.js"() {
  }
});

// node_modules/@aws-sdk/util-endpoints/dist-es/types/shared.js
var init_shared3 = __esm({
  "node_modules/@aws-sdk/util-endpoints/dist-es/types/shared.js"() {
  }
});

// node_modules/@aws-sdk/util-endpoints/dist-es/types/index.js
var init_types3 = __esm({
  "node_modules/@aws-sdk/util-endpoints/dist-es/types/index.js"() {
    init_EndpointError2();
    init_EndpointRuleObject3();
    init_ErrorRuleObject3();
    init_RuleSetObject3();
    init_TreeRuleObject3();
    init_shared3();
  }
});

// node_modules/@aws-sdk/util-endpoints/dist-es/index.js
var init_dist_es23 = __esm({
  "node_modules/@aws-sdk/util-endpoints/dist-es/index.js"() {
    init_aws();
    init_partition();
    init_isIpAddress2();
    init_resolveDefaultAwsRegionalEndpointsConfig();
    init_resolveEndpoint2();
    init_types3();
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/client/emitWarningIfUnsupportedVersion.js
var state, emitWarningIfUnsupportedVersion;
var init_emitWarningIfUnsupportedVersion = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/client/emitWarningIfUnsupportedVersion.js"() {
    state = {
      warningEmitted: false
    };
    emitWarningIfUnsupportedVersion = (version) => {
      if (version && !state.warningEmitted && parseInt(version.substring(1, version.indexOf("."))) < 20) {
        state.warningEmitted = true;
        process.emitWarning(`NodeDeprecationWarning: The AWS SDK for JavaScript (v3) will
no longer support Node.js ${version} in January 2026.

To continue receiving updates to AWS services, bug fixes, and security
updates please upgrade to a supported Node.js LTS version.

More information can be found at: https://a.co/c895JFp`);
      }
    };
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/client/setCredentialFeature.js
function setCredentialFeature(credentials, feature, value) {
  if (!credentials.$source) {
    credentials.$source = {};
  }
  credentials.$source[feature] = value;
  return credentials;
}
var init_setCredentialFeature = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/client/setCredentialFeature.js"() {
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/client/setFeature.js
function setFeature2(context, feature, value) {
  if (!context.__aws_sdk_context) {
    context.__aws_sdk_context = {
      features: {}
    };
  } else if (!context.__aws_sdk_context.features) {
    context.__aws_sdk_context.features = {};
  }
  context.__aws_sdk_context.features[feature] = value;
}
var init_setFeature2 = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/client/setFeature.js"() {
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/client/setTokenFeature.js
var init_setTokenFeature = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/client/setTokenFeature.js"() {
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/client/index.js
var init_client2 = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/client/index.js"() {
    init_emitWarningIfUnsupportedVersion();
    init_setCredentialFeature();
    init_setFeature2();
    init_setTokenFeature();
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/utils/getDateHeader.js
var getDateHeader;
var init_getDateHeader = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/utils/getDateHeader.js"() {
    init_dist_es2();
    getDateHeader = (response) => HttpResponse.isInstance(response) ? response.headers?.date ?? response.headers?.Date : void 0;
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/utils/getSkewCorrectedDate.js
var getSkewCorrectedDate;
var init_getSkewCorrectedDate = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/utils/getSkewCorrectedDate.js"() {
    getSkewCorrectedDate = (systemClockOffset) => new Date(Date.now() + systemClockOffset);
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/utils/isClockSkewed.js
var isClockSkewed;
var init_isClockSkewed = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/utils/isClockSkewed.js"() {
    init_getSkewCorrectedDate();
    isClockSkewed = (clockTime, systemClockOffset) => Math.abs(getSkewCorrectedDate(systemClockOffset).getTime() - clockTime) >= 3e5;
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/utils/getUpdatedSystemClockOffset.js
var getUpdatedSystemClockOffset;
var init_getUpdatedSystemClockOffset = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/utils/getUpdatedSystemClockOffset.js"() {
    init_isClockSkewed();
    getUpdatedSystemClockOffset = (clockTime, currentSystemClockOffset) => {
      const clockTimeInMs = Date.parse(clockTime);
      if (isClockSkewed(clockTimeInMs, currentSystemClockOffset)) {
        return clockTimeInMs - Date.now();
      }
      return currentSystemClockOffset;
    };
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/utils/index.js
var init_utils2 = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/utils/index.js"() {
    init_getDateHeader();
    init_getSkewCorrectedDate();
    init_getUpdatedSystemClockOffset();
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/aws_sdk/AwsSdkSigV4Signer.js
var throwSigningPropertyError, validateSigningProperties, AwsSdkSigV4Signer;
var init_AwsSdkSigV4Signer = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/aws_sdk/AwsSdkSigV4Signer.js"() {
    init_dist_es2();
    init_utils2();
    throwSigningPropertyError = (name, property) => {
      if (!property) {
        throw new Error(`Property \`${name}\` is not resolved for AWS SDK SigV4Auth`);
      }
      return property;
    };
    validateSigningProperties = async (signingProperties) => {
      const context = throwSigningPropertyError("context", signingProperties.context);
      const config = throwSigningPropertyError("config", signingProperties.config);
      const authScheme = context.endpointV2?.properties?.authSchemes?.[0];
      const signerFunction = throwSigningPropertyError("signer", config.signer);
      const signer = await signerFunction(authScheme);
      const signingRegion = signingProperties?.signingRegion;
      const signingRegionSet = signingProperties?.signingRegionSet;
      const signingName = signingProperties?.signingName;
      return {
        config,
        signer,
        signingRegion,
        signingRegionSet,
        signingName
      };
    };
    AwsSdkSigV4Signer = class {
      async sign(httpRequest2, identity, signingProperties) {
        if (!HttpRequest.isInstance(httpRequest2)) {
          throw new Error("The request is not an instance of `HttpRequest` and cannot be signed");
        }
        const validatedProps = await validateSigningProperties(signingProperties);
        const { config, signer } = validatedProps;
        let { signingRegion, signingName } = validatedProps;
        const handlerExecutionContext = signingProperties.context;
        if (handlerExecutionContext?.authSchemes?.length ?? 0 > 1) {
          const [first, second] = handlerExecutionContext.authSchemes;
          if (first?.name === "sigv4a" && second?.name === "sigv4") {
            signingRegion = second?.signingRegion ?? signingRegion;
            signingName = second?.signingName ?? signingName;
          }
        }
        const signedRequest = await signer.sign(httpRequest2, {
          signingDate: getSkewCorrectedDate(config.systemClockOffset),
          signingRegion,
          signingService: signingName
        });
        return signedRequest;
      }
      errorHandler(signingProperties) {
        return (error) => {
          const serverTime = error.ServerTime ?? getDateHeader(error.$response);
          if (serverTime) {
            const config = throwSigningPropertyError("config", signingProperties.config);
            const initialSystemClockOffset = config.systemClockOffset;
            config.systemClockOffset = getUpdatedSystemClockOffset(serverTime, config.systemClockOffset);
            const clockSkewCorrected = config.systemClockOffset !== initialSystemClockOffset;
            if (clockSkewCorrected && error.$metadata) {
              error.$metadata.clockSkewCorrected = true;
            }
          }
          throw error;
        };
      }
      successHandler(httpResponse, signingProperties) {
        const dateHeader = getDateHeader(httpResponse);
        if (dateHeader) {
          const config = throwSigningPropertyError("config", signingProperties.config);
          config.systemClockOffset = getUpdatedSystemClockOffset(dateHeader, config.systemClockOffset);
        }
      }
    };
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/utils/getArrayForCommaSeparatedString.js
var getArrayForCommaSeparatedString;
var init_getArrayForCommaSeparatedString = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/utils/getArrayForCommaSeparatedString.js"() {
    getArrayForCommaSeparatedString = (str) => typeof str === "string" && str.length > 0 ? str.split(",").map((item) => item.trim()) : [];
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/utils/getBearerTokenEnvKey.js
var getBearerTokenEnvKey;
var init_getBearerTokenEnvKey = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/utils/getBearerTokenEnvKey.js"() {
    getBearerTokenEnvKey = (signingName) => `AWS_BEARER_TOKEN_${signingName.replace(/[\s-]/g, "_").toUpperCase()}`;
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/aws_sdk/NODE_AUTH_SCHEME_PREFERENCE_OPTIONS.js
var NODE_AUTH_SCHEME_PREFERENCE_ENV_KEY, NODE_AUTH_SCHEME_PREFERENCE_CONFIG_KEY, NODE_AUTH_SCHEME_PREFERENCE_OPTIONS;
var init_NODE_AUTH_SCHEME_PREFERENCE_OPTIONS = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/aws_sdk/NODE_AUTH_SCHEME_PREFERENCE_OPTIONS.js"() {
    init_getArrayForCommaSeparatedString();
    init_getBearerTokenEnvKey();
    NODE_AUTH_SCHEME_PREFERENCE_ENV_KEY = "AWS_AUTH_SCHEME_PREFERENCE";
    NODE_AUTH_SCHEME_PREFERENCE_CONFIG_KEY = "auth_scheme_preference";
    NODE_AUTH_SCHEME_PREFERENCE_OPTIONS = {
      environmentVariableSelector: (env2, options) => {
        if (options?.signingName) {
          const bearerTokenKey = getBearerTokenEnvKey(options.signingName);
          if (bearerTokenKey in env2)
            return ["httpBearerAuth"];
        }
        if (!(NODE_AUTH_SCHEME_PREFERENCE_ENV_KEY in env2))
          return void 0;
        return getArrayForCommaSeparatedString(env2[NODE_AUTH_SCHEME_PREFERENCE_ENV_KEY]);
      },
      configFileSelector: (profile) => {
        if (!(NODE_AUTH_SCHEME_PREFERENCE_CONFIG_KEY in profile))
          return void 0;
        return getArrayForCommaSeparatedString(profile[NODE_AUTH_SCHEME_PREFERENCE_CONFIG_KEY]);
      },
      default: []
    };
  }
});

// node_modules/@smithy/property-provider/dist-es/ProviderError.js
var ProviderError;
var init_ProviderError = __esm({
  "node_modules/@smithy/property-provider/dist-es/ProviderError.js"() {
    ProviderError = class _ProviderError extends Error {
      name = "ProviderError";
      tryNextLink;
      constructor(message, options = true) {
        let logger2;
        let tryNextLink = true;
        if (typeof options === "boolean") {
          logger2 = void 0;
          tryNextLink = options;
        } else if (options != null && typeof options === "object") {
          logger2 = options.logger;
          tryNextLink = options.tryNextLink ?? true;
        }
        super(message);
        this.tryNextLink = tryNextLink;
        Object.setPrototypeOf(this, _ProviderError.prototype);
        logger2?.debug?.(`@smithy/property-provider ${tryNextLink ? "->" : "(!)"} ${message}`);
      }
      static from(error, options = true) {
        return Object.assign(new this(error.message, options), error);
      }
    };
  }
});

// node_modules/@smithy/property-provider/dist-es/CredentialsProviderError.js
var CredentialsProviderError;
var init_CredentialsProviderError = __esm({
  "node_modules/@smithy/property-provider/dist-es/CredentialsProviderError.js"() {
    init_ProviderError();
    CredentialsProviderError = class _CredentialsProviderError extends ProviderError {
      name = "CredentialsProviderError";
      constructor(message, options = true) {
        super(message, options);
        Object.setPrototypeOf(this, _CredentialsProviderError.prototype);
      }
    };
  }
});

// node_modules/@smithy/property-provider/dist-es/TokenProviderError.js
var TokenProviderError;
var init_TokenProviderError = __esm({
  "node_modules/@smithy/property-provider/dist-es/TokenProviderError.js"() {
    init_ProviderError();
    TokenProviderError = class _TokenProviderError extends ProviderError {
      name = "TokenProviderError";
      constructor(message, options = true) {
        super(message, options);
        Object.setPrototypeOf(this, _TokenProviderError.prototype);
      }
    };
  }
});

// node_modules/@smithy/property-provider/dist-es/chain.js
var chain;
var init_chain = __esm({
  "node_modules/@smithy/property-provider/dist-es/chain.js"() {
    init_ProviderError();
    chain = (...providers) => async () => {
      if (providers.length === 0) {
        throw new ProviderError("No providers in chain");
      }
      let lastProviderError;
      for (const provider of providers) {
        try {
          const credentials = await provider();
          return credentials;
        } catch (err) {
          lastProviderError = err;
          if (err?.tryNextLink) {
            continue;
          }
          throw err;
        }
      }
      throw lastProviderError;
    };
  }
});

// node_modules/@smithy/property-provider/dist-es/fromStatic.js
var fromStatic;
var init_fromStatic = __esm({
  "node_modules/@smithy/property-provider/dist-es/fromStatic.js"() {
    fromStatic = (staticValue) => () => Promise.resolve(staticValue);
  }
});

// node_modules/@smithy/property-provider/dist-es/memoize.js
var memoize;
var init_memoize = __esm({
  "node_modules/@smithy/property-provider/dist-es/memoize.js"() {
    memoize = (provider, isExpired, requiresRefresh) => {
      let resolved;
      let pending;
      let hasResult;
      let isConstant = false;
      const coalesceProvider = async () => {
        if (!pending) {
          pending = provider();
        }
        try {
          resolved = await pending;
          hasResult = true;
          isConstant = false;
        } finally {
          pending = void 0;
        }
        return resolved;
      };
      if (isExpired === void 0) {
        return async (options) => {
          if (!hasResult || options?.forceRefresh) {
            resolved = await coalesceProvider();
          }
          return resolved;
        };
      }
      return async (options) => {
        if (!hasResult || options?.forceRefresh) {
          resolved = await coalesceProvider();
        }
        if (isConstant) {
          return resolved;
        }
        if (requiresRefresh && !requiresRefresh(resolved)) {
          isConstant = true;
          return resolved;
        }
        if (isExpired(resolved)) {
          await coalesceProvider();
          return resolved;
        }
        return resolved;
      };
    };
  }
});

// node_modules/@smithy/property-provider/dist-es/index.js
var init_dist_es24 = __esm({
  "node_modules/@smithy/property-provider/dist-es/index.js"() {
    init_CredentialsProviderError();
    init_ProviderError();
    init_TokenProviderError();
    init_chain();
    init_fromStatic();
    init_memoize();
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/aws_sdk/resolveAwsSdkSigV4AConfig.js
var init_resolveAwsSdkSigV4AConfig = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/aws_sdk/resolveAwsSdkSigV4AConfig.js"() {
  }
});

// node_modules/@smithy/signature-v4/dist-es/constants.js
var ALGORITHM_QUERY_PARAM, CREDENTIAL_QUERY_PARAM, AMZ_DATE_QUERY_PARAM, SIGNED_HEADERS_QUERY_PARAM, EXPIRES_QUERY_PARAM, SIGNATURE_QUERY_PARAM, TOKEN_QUERY_PARAM, AUTH_HEADER, AMZ_DATE_HEADER, DATE_HEADER, GENERATED_HEADERS, SIGNATURE_HEADER, SHA256_HEADER, TOKEN_HEADER, ALWAYS_UNSIGNABLE_HEADERS, PROXY_HEADER_PATTERN, SEC_HEADER_PATTERN, ALGORITHM_IDENTIFIER, EVENT_ALGORITHM_IDENTIFIER, UNSIGNED_PAYLOAD, MAX_CACHE_SIZE, KEY_TYPE_IDENTIFIER, MAX_PRESIGNED_TTL;
var init_constants2 = __esm({
  "node_modules/@smithy/signature-v4/dist-es/constants.js"() {
    ALGORITHM_QUERY_PARAM = "X-Amz-Algorithm";
    CREDENTIAL_QUERY_PARAM = "X-Amz-Credential";
    AMZ_DATE_QUERY_PARAM = "X-Amz-Date";
    SIGNED_HEADERS_QUERY_PARAM = "X-Amz-SignedHeaders";
    EXPIRES_QUERY_PARAM = "X-Amz-Expires";
    SIGNATURE_QUERY_PARAM = "X-Amz-Signature";
    TOKEN_QUERY_PARAM = "X-Amz-Security-Token";
    AUTH_HEADER = "authorization";
    AMZ_DATE_HEADER = AMZ_DATE_QUERY_PARAM.toLowerCase();
    DATE_HEADER = "date";
    GENERATED_HEADERS = [AUTH_HEADER, AMZ_DATE_HEADER, DATE_HEADER];
    SIGNATURE_HEADER = SIGNATURE_QUERY_PARAM.toLowerCase();
    SHA256_HEADER = "x-amz-content-sha256";
    TOKEN_HEADER = TOKEN_QUERY_PARAM.toLowerCase();
    ALWAYS_UNSIGNABLE_HEADERS = {
      authorization: true,
      "cache-control": true,
      connection: true,
      expect: true,
      from: true,
      "keep-alive": true,
      "max-forwards": true,
      pragma: true,
      referer: true,
      te: true,
      trailer: true,
      "transfer-encoding": true,
      upgrade: true,
      "user-agent": true,
      "x-amzn-trace-id": true
    };
    PROXY_HEADER_PATTERN = /^proxy-/;
    SEC_HEADER_PATTERN = /^sec-/;
    ALGORITHM_IDENTIFIER = "AWS4-HMAC-SHA256";
    EVENT_ALGORITHM_IDENTIFIER = "AWS4-HMAC-SHA256-PAYLOAD";
    UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";
    MAX_CACHE_SIZE = 50;
    KEY_TYPE_IDENTIFIER = "aws4_request";
    MAX_PRESIGNED_TTL = 60 * 60 * 24 * 7;
  }
});

// node_modules/@smithy/signature-v4/dist-es/credentialDerivation.js
var signingKeyCache, cacheQueue, createScope, getSigningKey, hmac;
var init_credentialDerivation = __esm({
  "node_modules/@smithy/signature-v4/dist-es/credentialDerivation.js"() {
    init_dist_es16();
    init_dist_es10();
    init_constants2();
    signingKeyCache = {};
    cacheQueue = [];
    createScope = (shortDate, region, service) => `${shortDate}/${region}/${service}/${KEY_TYPE_IDENTIFIER}`;
    getSigningKey = async (sha256Constructor, credentials, shortDate, region, service) => {
      const credsHash = await hmac(sha256Constructor, credentials.secretAccessKey, credentials.accessKeyId);
      const cacheKey = `${shortDate}:${region}:${service}:${toHex(credsHash)}:${credentials.sessionToken}`;
      if (cacheKey in signingKeyCache) {
        return signingKeyCache[cacheKey];
      }
      cacheQueue.push(cacheKey);
      while (cacheQueue.length > MAX_CACHE_SIZE) {
        delete signingKeyCache[cacheQueue.shift()];
      }
      let key = `AWS4${credentials.secretAccessKey}`;
      for (const signable of [shortDate, region, service, KEY_TYPE_IDENTIFIER]) {
        key = await hmac(sha256Constructor, key, signable);
      }
      return signingKeyCache[cacheKey] = key;
    };
    hmac = (ctor, secret, data) => {
      const hash = new ctor(secret);
      hash.update(toUint8Array(data));
      return hash.digest();
    };
  }
});

// node_modules/@smithy/signature-v4/dist-es/getCanonicalHeaders.js
var getCanonicalHeaders;
var init_getCanonicalHeaders = __esm({
  "node_modules/@smithy/signature-v4/dist-es/getCanonicalHeaders.js"() {
    init_constants2();
    getCanonicalHeaders = ({ headers }, unsignableHeaders, signableHeaders) => {
      const canonical = {};
      for (const headerName of Object.keys(headers).sort()) {
        if (headers[headerName] == void 0) {
          continue;
        }
        const canonicalHeaderName = headerName.toLowerCase();
        if (canonicalHeaderName in ALWAYS_UNSIGNABLE_HEADERS || unsignableHeaders?.has(canonicalHeaderName) || PROXY_HEADER_PATTERN.test(canonicalHeaderName) || SEC_HEADER_PATTERN.test(canonicalHeaderName)) {
          if (!signableHeaders || signableHeaders && !signableHeaders.has(canonicalHeaderName)) {
            continue;
          }
        }
        canonical[canonicalHeaderName] = headers[headerName].trim().replace(/\s+/g, " ");
      }
      return canonical;
    };
  }
});

// node_modules/@smithy/signature-v4/dist-es/getPayloadHash.js
var getPayloadHash;
var init_getPayloadHash = __esm({
  "node_modules/@smithy/signature-v4/dist-es/getPayloadHash.js"() {
    init_dist_es8();
    init_dist_es16();
    init_dist_es10();
    init_constants2();
    getPayloadHash = async ({ headers, body }, hashConstructor) => {
      for (const headerName of Object.keys(headers)) {
        if (headerName.toLowerCase() === SHA256_HEADER) {
          return headers[headerName];
        }
      }
      if (body == void 0) {
        return "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
      } else if (typeof body === "string" || ArrayBuffer.isView(body) || isArrayBuffer(body)) {
        const hashCtor = new hashConstructor();
        hashCtor.update(toUint8Array(body));
        return toHex(await hashCtor.digest());
      }
      return UNSIGNED_PAYLOAD;
    };
  }
});

// node_modules/@smithy/signature-v4/dist-es/HeaderFormatter.js
function negate(bytes) {
  for (let i6 = 0; i6 < 8; i6++) {
    bytes[i6] ^= 255;
  }
  for (let i6 = 7; i6 > -1; i6--) {
    bytes[i6]++;
    if (bytes[i6] !== 0)
      break;
  }
}
var HeaderFormatter, HEADER_VALUE_TYPE, UUID_PATTERN, Int64;
var init_HeaderFormatter = __esm({
  "node_modules/@smithy/signature-v4/dist-es/HeaderFormatter.js"() {
    init_dist_es16();
    init_dist_es10();
    HeaderFormatter = class {
      format(headers) {
        const chunks = [];
        for (const headerName of Object.keys(headers)) {
          const bytes = fromUtf8(headerName);
          chunks.push(Uint8Array.from([bytes.byteLength]), bytes, this.formatHeaderValue(headers[headerName]));
        }
        const out = new Uint8Array(chunks.reduce((carry, bytes) => carry + bytes.byteLength, 0));
        let position = 0;
        for (const chunk of chunks) {
          out.set(chunk, position);
          position += chunk.byteLength;
        }
        return out;
      }
      formatHeaderValue(header) {
        switch (header.type) {
          case "boolean":
            return Uint8Array.from([header.value ? 0 : 1]);
          case "byte":
            return Uint8Array.from([2, header.value]);
          case "short":
            const shortView = new DataView(new ArrayBuffer(3));
            shortView.setUint8(0, 3);
            shortView.setInt16(1, header.value, false);
            return new Uint8Array(shortView.buffer);
          case "integer":
            const intView = new DataView(new ArrayBuffer(5));
            intView.setUint8(0, 4);
            intView.setInt32(1, header.value, false);
            return new Uint8Array(intView.buffer);
          case "long":
            const longBytes = new Uint8Array(9);
            longBytes[0] = 5;
            longBytes.set(header.value.bytes, 1);
            return longBytes;
          case "binary":
            const binView = new DataView(new ArrayBuffer(3 + header.value.byteLength));
            binView.setUint8(0, 6);
            binView.setUint16(1, header.value.byteLength, false);
            const binBytes = new Uint8Array(binView.buffer);
            binBytes.set(header.value, 3);
            return binBytes;
          case "string":
            const utf8Bytes = fromUtf8(header.value);
            const strView = new DataView(new ArrayBuffer(3 + utf8Bytes.byteLength));
            strView.setUint8(0, 7);
            strView.setUint16(1, utf8Bytes.byteLength, false);
            const strBytes = new Uint8Array(strView.buffer);
            strBytes.set(utf8Bytes, 3);
            return strBytes;
          case "timestamp":
            const tsBytes = new Uint8Array(9);
            tsBytes[0] = 8;
            tsBytes.set(Int64.fromNumber(header.value.valueOf()).bytes, 1);
            return tsBytes;
          case "uuid":
            if (!UUID_PATTERN.test(header.value)) {
              throw new Error(`Invalid UUID received: ${header.value}`);
            }
            const uuidBytes = new Uint8Array(17);
            uuidBytes[0] = 9;
            uuidBytes.set(fromHex(header.value.replace(/\-/g, "")), 1);
            return uuidBytes;
        }
      }
    };
    (function(HEADER_VALUE_TYPE2) {
      HEADER_VALUE_TYPE2[HEADER_VALUE_TYPE2["boolTrue"] = 0] = "boolTrue";
      HEADER_VALUE_TYPE2[HEADER_VALUE_TYPE2["boolFalse"] = 1] = "boolFalse";
      HEADER_VALUE_TYPE2[HEADER_VALUE_TYPE2["byte"] = 2] = "byte";
      HEADER_VALUE_TYPE2[HEADER_VALUE_TYPE2["short"] = 3] = "short";
      HEADER_VALUE_TYPE2[HEADER_VALUE_TYPE2["integer"] = 4] = "integer";
      HEADER_VALUE_TYPE2[HEADER_VALUE_TYPE2["long"] = 5] = "long";
      HEADER_VALUE_TYPE2[HEADER_VALUE_TYPE2["byteArray"] = 6] = "byteArray";
      HEADER_VALUE_TYPE2[HEADER_VALUE_TYPE2["string"] = 7] = "string";
      HEADER_VALUE_TYPE2[HEADER_VALUE_TYPE2["timestamp"] = 8] = "timestamp";
      HEADER_VALUE_TYPE2[HEADER_VALUE_TYPE2["uuid"] = 9] = "uuid";
    })(HEADER_VALUE_TYPE || (HEADER_VALUE_TYPE = {}));
    UUID_PATTERN = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
    Int64 = class _Int64 {
      bytes;
      constructor(bytes) {
        this.bytes = bytes;
        if (bytes.byteLength !== 8) {
          throw new Error("Int64 buffers must be exactly 8 bytes");
        }
      }
      static fromNumber(number) {
        if (number > 9223372036854776e3 || number < -9223372036854776e3) {
          throw new Error(`${number} is too large (or, if negative, too small) to represent as an Int64`);
        }
        const bytes = new Uint8Array(8);
        for (let i6 = 7, remaining = Math.abs(Math.round(number)); i6 > -1 && remaining > 0; i6--, remaining /= 256) {
          bytes[i6] = remaining;
        }
        if (number < 0) {
          negate(bytes);
        }
        return new _Int64(bytes);
      }
      valueOf() {
        const bytes = this.bytes.slice(0);
        const negative = bytes[0] & 128;
        if (negative) {
          negate(bytes);
        }
        return parseInt(toHex(bytes), 16) * (negative ? -1 : 1);
      }
      toString() {
        return String(this.valueOf());
      }
    };
  }
});

// node_modules/@smithy/signature-v4/dist-es/headerUtil.js
var hasHeader;
var init_headerUtil = __esm({
  "node_modules/@smithy/signature-v4/dist-es/headerUtil.js"() {
    hasHeader = (soughtHeader, headers) => {
      soughtHeader = soughtHeader.toLowerCase();
      for (const headerName of Object.keys(headers)) {
        if (soughtHeader === headerName.toLowerCase()) {
          return true;
        }
      }
      return false;
    };
  }
});

// node_modules/@smithy/signature-v4/dist-es/moveHeadersToQuery.js
var moveHeadersToQuery;
var init_moveHeadersToQuery = __esm({
  "node_modules/@smithy/signature-v4/dist-es/moveHeadersToQuery.js"() {
    init_dist_es2();
    moveHeadersToQuery = (request2, options = {}) => {
      const { headers, query = {} } = HttpRequest.clone(request2);
      for (const name of Object.keys(headers)) {
        const lname = name.toLowerCase();
        if (lname.slice(0, 6) === "x-amz-" && !options.unhoistableHeaders?.has(lname) || options.hoistableHeaders?.has(lname)) {
          query[name] = headers[name];
          delete headers[name];
        }
      }
      return {
        ...request2,
        headers,
        query
      };
    };
  }
});

// node_modules/@smithy/signature-v4/dist-es/prepareRequest.js
var prepareRequest;
var init_prepareRequest = __esm({
  "node_modules/@smithy/signature-v4/dist-es/prepareRequest.js"() {
    init_dist_es2();
    init_constants2();
    prepareRequest = (request2) => {
      request2 = HttpRequest.clone(request2);
      for (const headerName of Object.keys(request2.headers)) {
        if (GENERATED_HEADERS.indexOf(headerName.toLowerCase()) > -1) {
          delete request2.headers[headerName];
        }
      }
      return request2;
    };
  }
});

// node_modules/@smithy/signature-v4/dist-es/getCanonicalQuery.js
var getCanonicalQuery;
var init_getCanonicalQuery = __esm({
  "node_modules/@smithy/signature-v4/dist-es/getCanonicalQuery.js"() {
    init_dist_es12();
    init_constants2();
    getCanonicalQuery = ({ query = {} }) => {
      const keys = [];
      const serialized = {};
      for (const key of Object.keys(query)) {
        if (key.toLowerCase() === SIGNATURE_HEADER) {
          continue;
        }
        const encodedKey = escapeUri(key);
        keys.push(encodedKey);
        const value = query[key];
        if (typeof value === "string") {
          serialized[encodedKey] = `${encodedKey}=${escapeUri(value)}`;
        } else if (Array.isArray(value)) {
          serialized[encodedKey] = value.slice(0).reduce((encoded, value2) => encoded.concat([`${encodedKey}=${escapeUri(value2)}`]), []).sort().join("&");
        }
      }
      return keys.sort().map((key) => serialized[key]).filter((serialized2) => serialized2).join("&");
    };
  }
});

// node_modules/@smithy/signature-v4/dist-es/utilDate.js
var iso8601, toDate;
var init_utilDate = __esm({
  "node_modules/@smithy/signature-v4/dist-es/utilDate.js"() {
    iso8601 = (time2) => toDate(time2).toISOString().replace(/\.\d{3}Z$/, "Z");
    toDate = (time2) => {
      if (typeof time2 === "number") {
        return new Date(time2 * 1e3);
      }
      if (typeof time2 === "string") {
        if (Number(time2)) {
          return new Date(Number(time2) * 1e3);
        }
        return new Date(time2);
      }
      return time2;
    };
  }
});

// node_modules/@smithy/signature-v4/dist-es/SignatureV4Base.js
var SignatureV4Base;
var init_SignatureV4Base = __esm({
  "node_modules/@smithy/signature-v4/dist-es/SignatureV4Base.js"() {
    init_dist_es16();
    init_dist_es6();
    init_dist_es12();
    init_dist_es10();
    init_getCanonicalQuery();
    init_utilDate();
    SignatureV4Base = class {
      service;
      regionProvider;
      credentialProvider;
      sha256;
      uriEscapePath;
      applyChecksum;
      constructor({ applyChecksum, credentials, region, service, sha256, uriEscapePath = true }) {
        this.service = service;
        this.sha256 = sha256;
        this.uriEscapePath = uriEscapePath;
        this.applyChecksum = typeof applyChecksum === "boolean" ? applyChecksum : true;
        this.regionProvider = normalizeProvider(region);
        this.credentialProvider = normalizeProvider(credentials);
      }
      createCanonicalRequest(request2, canonicalHeaders, payloadHash) {
        const sortedHeaders = Object.keys(canonicalHeaders).sort();
        return `${request2.method}
${this.getCanonicalPath(request2)}
${getCanonicalQuery(request2)}
${sortedHeaders.map((name) => `${name}:${canonicalHeaders[name]}`).join("\n")}

${sortedHeaders.join(";")}
${payloadHash}`;
      }
      async createStringToSign(longDate, credentialScope, canonicalRequest, algorithmIdentifier) {
        const hash = new this.sha256();
        hash.update(toUint8Array(canonicalRequest));
        const hashedRequest = await hash.digest();
        return `${algorithmIdentifier}
${longDate}
${credentialScope}
${toHex(hashedRequest)}`;
      }
      getCanonicalPath({ path }) {
        if (this.uriEscapePath) {
          const normalizedPathSegments = [];
          for (const pathSegment of path.split("/")) {
            if (pathSegment?.length === 0)
              continue;
            if (pathSegment === ".")
              continue;
            if (pathSegment === "..") {
              normalizedPathSegments.pop();
            } else {
              normalizedPathSegments.push(pathSegment);
            }
          }
          const normalizedPath = `${path?.startsWith("/") ? "/" : ""}${normalizedPathSegments.join("/")}${normalizedPathSegments.length > 0 && path?.endsWith("/") ? "/" : ""}`;
          const doubleEncoded = escapeUri(normalizedPath);
          return doubleEncoded.replace(/%2F/g, "/");
        }
        return path;
      }
      validateResolvedCredentials(credentials) {
        if (typeof credentials !== "object" || typeof credentials.accessKeyId !== "string" || typeof credentials.secretAccessKey !== "string") {
          throw new Error("Resolved credential object is not valid");
        }
      }
      formatDate(now) {
        const longDate = iso8601(now).replace(/[\-:]/g, "");
        return {
          longDate,
          shortDate: longDate.slice(0, 8)
        };
      }
      getCanonicalHeaderList(headers) {
        return Object.keys(headers).sort().join(";");
      }
    };
  }
});

// node_modules/@smithy/signature-v4/dist-es/SignatureV4.js
var SignatureV4;
var init_SignatureV4 = __esm({
  "node_modules/@smithy/signature-v4/dist-es/SignatureV4.js"() {
    init_dist_es16();
    init_dist_es10();
    init_constants2();
    init_credentialDerivation();
    init_getCanonicalHeaders();
    init_getPayloadHash();
    init_HeaderFormatter();
    init_headerUtil();
    init_moveHeadersToQuery();
    init_prepareRequest();
    init_SignatureV4Base();
    SignatureV4 = class extends SignatureV4Base {
      headerFormatter = new HeaderFormatter();
      constructor({ applyChecksum, credentials, region, service, sha256, uriEscapePath = true }) {
        super({
          applyChecksum,
          credentials,
          region,
          service,
          sha256,
          uriEscapePath
        });
      }
      async presign(originalRequest, options = {}) {
        const { signingDate = /* @__PURE__ */ new Date(), expiresIn = 3600, unsignableHeaders, unhoistableHeaders, signableHeaders, hoistableHeaders, signingRegion, signingService } = options;
        const credentials = await this.credentialProvider();
        this.validateResolvedCredentials(credentials);
        const region = signingRegion ?? await this.regionProvider();
        const { longDate, shortDate } = this.formatDate(signingDate);
        if (expiresIn > MAX_PRESIGNED_TTL) {
          return Promise.reject("Signature version 4 presigned URLs must have an expiration date less than one week in the future");
        }
        const scope = createScope(shortDate, region, signingService ?? this.service);
        const request2 = moveHeadersToQuery(prepareRequest(originalRequest), { unhoistableHeaders, hoistableHeaders });
        if (credentials.sessionToken) {
          request2.query[TOKEN_QUERY_PARAM] = credentials.sessionToken;
        }
        request2.query[ALGORITHM_QUERY_PARAM] = ALGORITHM_IDENTIFIER;
        request2.query[CREDENTIAL_QUERY_PARAM] = `${credentials.accessKeyId}/${scope}`;
        request2.query[AMZ_DATE_QUERY_PARAM] = longDate;
        request2.query[EXPIRES_QUERY_PARAM] = expiresIn.toString(10);
        const canonicalHeaders = getCanonicalHeaders(request2, unsignableHeaders, signableHeaders);
        request2.query[SIGNED_HEADERS_QUERY_PARAM] = this.getCanonicalHeaderList(canonicalHeaders);
        request2.query[SIGNATURE_QUERY_PARAM] = await this.getSignature(longDate, scope, this.getSigningKey(credentials, region, shortDate, signingService), this.createCanonicalRequest(request2, canonicalHeaders, await getPayloadHash(originalRequest, this.sha256)));
        return request2;
      }
      async sign(toSign, options) {
        if (typeof toSign === "string") {
          return this.signString(toSign, options);
        } else if (toSign.headers && toSign.payload) {
          return this.signEvent(toSign, options);
        } else if (toSign.message) {
          return this.signMessage(toSign, options);
        } else {
          return this.signRequest(toSign, options);
        }
      }
      async signEvent({ headers, payload }, { signingDate = /* @__PURE__ */ new Date(), priorSignature, signingRegion, signingService }) {
        const region = signingRegion ?? await this.regionProvider();
        const { shortDate, longDate } = this.formatDate(signingDate);
        const scope = createScope(shortDate, region, signingService ?? this.service);
        const hashedPayload = await getPayloadHash({ headers: {}, body: payload }, this.sha256);
        const hash = new this.sha256();
        hash.update(headers);
        const hashedHeaders = toHex(await hash.digest());
        const stringToSign = [
          EVENT_ALGORITHM_IDENTIFIER,
          longDate,
          scope,
          priorSignature,
          hashedHeaders,
          hashedPayload
        ].join("\n");
        return this.signString(stringToSign, { signingDate, signingRegion: region, signingService });
      }
      async signMessage(signableMessage, { signingDate = /* @__PURE__ */ new Date(), signingRegion, signingService }) {
        const promise = this.signEvent({
          headers: this.headerFormatter.format(signableMessage.message.headers),
          payload: signableMessage.message.body
        }, {
          signingDate,
          signingRegion,
          signingService,
          priorSignature: signableMessage.priorSignature
        });
        return promise.then((signature) => {
          return { message: signableMessage.message, signature };
        });
      }
      async signString(stringToSign, { signingDate = /* @__PURE__ */ new Date(), signingRegion, signingService } = {}) {
        const credentials = await this.credentialProvider();
        this.validateResolvedCredentials(credentials);
        const region = signingRegion ?? await this.regionProvider();
        const { shortDate } = this.formatDate(signingDate);
        const hash = new this.sha256(await this.getSigningKey(credentials, region, shortDate, signingService));
        hash.update(toUint8Array(stringToSign));
        return toHex(await hash.digest());
      }
      async signRequest(requestToSign, { signingDate = /* @__PURE__ */ new Date(), signableHeaders, unsignableHeaders, signingRegion, signingService } = {}) {
        const credentials = await this.credentialProvider();
        this.validateResolvedCredentials(credentials);
        const region = signingRegion ?? await this.regionProvider();
        const request2 = prepareRequest(requestToSign);
        const { longDate, shortDate } = this.formatDate(signingDate);
        const scope = createScope(shortDate, region, signingService ?? this.service);
        request2.headers[AMZ_DATE_HEADER] = longDate;
        if (credentials.sessionToken) {
          request2.headers[TOKEN_HEADER] = credentials.sessionToken;
        }
        const payloadHash = await getPayloadHash(request2, this.sha256);
        if (!hasHeader(SHA256_HEADER, request2.headers) && this.applyChecksum) {
          request2.headers[SHA256_HEADER] = payloadHash;
        }
        const canonicalHeaders = getCanonicalHeaders(request2, unsignableHeaders, signableHeaders);
        const signature = await this.getSignature(longDate, scope, this.getSigningKey(credentials, region, shortDate, signingService), this.createCanonicalRequest(request2, canonicalHeaders, payloadHash));
        request2.headers[AUTH_HEADER] = `${ALGORITHM_IDENTIFIER} Credential=${credentials.accessKeyId}/${scope}, SignedHeaders=${this.getCanonicalHeaderList(canonicalHeaders)}, Signature=${signature}`;
        return request2;
      }
      async getSignature(longDate, credentialScope, keyPromise, canonicalRequest) {
        const stringToSign = await this.createStringToSign(longDate, credentialScope, canonicalRequest, ALGORITHM_IDENTIFIER);
        const hash = new this.sha256(await keyPromise);
        hash.update(toUint8Array(stringToSign));
        return toHex(await hash.digest());
      }
      getSigningKey(credentials, region, shortDate, service) {
        return getSigningKey(this.sha256, credentials, shortDate, region, service || this.service);
      }
    };
  }
});

// node_modules/@smithy/signature-v4/dist-es/signature-v4a-container.js
var init_signature_v4a_container = __esm({
  "node_modules/@smithy/signature-v4/dist-es/signature-v4a-container.js"() {
  }
});

// node_modules/@smithy/signature-v4/dist-es/index.js
var init_dist_es25 = __esm({
  "node_modules/@smithy/signature-v4/dist-es/index.js"() {
    init_SignatureV4();
    init_constants2();
    init_credentialDerivation();
    init_signature_v4a_container();
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/aws_sdk/resolveAwsSdkSigV4Config.js
function normalizeCredentialProvider(config, { credentials, credentialDefaultProvider }) {
  let credentialsProvider;
  if (credentials) {
    if (!credentials?.memoized) {
      credentialsProvider = memoizeIdentityProvider(credentials, isIdentityExpired, doesIdentityRequireRefresh);
    } else {
      credentialsProvider = credentials;
    }
  } else {
    if (credentialDefaultProvider) {
      credentialsProvider = normalizeProvider2(credentialDefaultProvider(Object.assign({}, config, {
        parentClientConfig: config
      })));
    } else {
      credentialsProvider = async () => {
        throw new Error("@aws-sdk/core::resolveAwsSdkSigV4Config - `credentials` not provided and no credentialDefaultProvider was configured.");
      };
    }
  }
  credentialsProvider.memoized = true;
  return credentialsProvider;
}
function bindCallerConfig(config, credentialsProvider) {
  if (credentialsProvider.configBound) {
    return credentialsProvider;
  }
  const fn = async (options) => credentialsProvider({ ...options, callerClientConfig: config });
  fn.memoized = credentialsProvider.memoized;
  fn.configBound = true;
  return fn;
}
var resolveAwsSdkSigV4Config;
var init_resolveAwsSdkSigV4Config = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/aws_sdk/resolveAwsSdkSigV4Config.js"() {
    init_client2();
    init_dist_es19();
    init_dist_es25();
    resolveAwsSdkSigV4Config = (config) => {
      let inputCredentials = config.credentials;
      let isUserSupplied = !!config.credentials;
      let resolvedCredentials = void 0;
      Object.defineProperty(config, "credentials", {
        set(credentials) {
          if (credentials && credentials !== inputCredentials && credentials !== resolvedCredentials) {
            isUserSupplied = true;
          }
          inputCredentials = credentials;
          const memoizedProvider = normalizeCredentialProvider(config, {
            credentials: inputCredentials,
            credentialDefaultProvider: config.credentialDefaultProvider
          });
          const boundProvider = bindCallerConfig(config, memoizedProvider);
          if (isUserSupplied && !boundProvider.attributed) {
            resolvedCredentials = async (options) => boundProvider(options).then((creds) => setCredentialFeature(creds, "CREDENTIALS_CODE", "e"));
            resolvedCredentials.memoized = boundProvider.memoized;
            resolvedCredentials.configBound = boundProvider.configBound;
            resolvedCredentials.attributed = true;
          } else {
            resolvedCredentials = boundProvider;
          }
        },
        get() {
          return resolvedCredentials;
        },
        enumerable: true,
        configurable: true
      });
      config.credentials = inputCredentials;
      const { signingEscapePath = true, systemClockOffset = config.systemClockOffset || 0, sha256 } = config;
      let signer;
      if (config.signer) {
        signer = normalizeProvider2(config.signer);
      } else if (config.regionInfoProvider) {
        signer = () => normalizeProvider2(config.region)().then(async (region) => [
          await config.regionInfoProvider(region, {
            useFipsEndpoint: await config.useFipsEndpoint(),
            useDualstackEndpoint: await config.useDualstackEndpoint()
          }) || {},
          region
        ]).then(([regionInfo, region]) => {
          const { signingRegion, signingService } = regionInfo;
          config.signingRegion = config.signingRegion || signingRegion || region;
          config.signingName = config.signingName || signingService || config.serviceId;
          const params = {
            ...config,
            credentials: config.credentials,
            region: config.signingRegion,
            service: config.signingName,
            sha256,
            uriEscapePath: signingEscapePath
          };
          const SignerCtor = config.signerConstructor || SignatureV4;
          return new SignerCtor(params);
        });
      } else {
        signer = async (authScheme) => {
          authScheme = Object.assign({}, {
            name: "sigv4",
            signingName: config.signingName || config.defaultSigningName,
            signingRegion: await normalizeProvider2(config.region)(),
            properties: {}
          }, authScheme);
          const signingRegion = authScheme.signingRegion;
          const signingService = authScheme.signingName;
          config.signingRegion = config.signingRegion || signingRegion;
          config.signingName = config.signingName || signingService || config.serviceId;
          const params = {
            ...config,
            credentials: config.credentials,
            region: config.signingRegion,
            service: config.signingName,
            sha256,
            uriEscapePath: signingEscapePath
          };
          const SignerCtor = config.signerConstructor || SignatureV4;
          return new SignerCtor(params);
        };
      }
      const resolvedConfig = Object.assign(config, {
        systemClockOffset,
        signingEscapePath,
        signer
      });
      return resolvedConfig;
    };
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/aws_sdk/index.js
var init_aws_sdk = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/aws_sdk/index.js"() {
    init_AwsSdkSigV4Signer();
    init_NODE_AUTH_SCHEME_PREFERENCE_OPTIONS();
    init_resolveAwsSdkSigV4AConfig();
    init_resolveAwsSdkSigV4Config();
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/index.js
var init_httpAuthSchemes2 = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/httpAuthSchemes/index.js"() {
    init_aws_sdk();
    init_getBearerTokenEnvKey();
  }
});

// node_modules/@smithy/middleware-stack/dist-es/MiddlewareStack.js
var getAllAliases, getMiddlewareNameWithAliases, constructStack, stepWeights, priorityWeights;
var init_MiddlewareStack = __esm({
  "node_modules/@smithy/middleware-stack/dist-es/MiddlewareStack.js"() {
    getAllAliases = (name, aliases) => {
      const _aliases = [];
      if (name) {
        _aliases.push(name);
      }
      if (aliases) {
        for (const alias of aliases) {
          _aliases.push(alias);
        }
      }
      return _aliases;
    };
    getMiddlewareNameWithAliases = (name, aliases) => {
      return `${name || "anonymous"}${aliases && aliases.length > 0 ? ` (a.k.a. ${aliases.join(",")})` : ""}`;
    };
    constructStack = () => {
      let absoluteEntries = [];
      let relativeEntries = [];
      let identifyOnResolve = false;
      const entriesNameSet = /* @__PURE__ */ new Set();
      const sort = (entries) => entries.sort((a6, b6) => stepWeights[b6.step] - stepWeights[a6.step] || priorityWeights[b6.priority || "normal"] - priorityWeights[a6.priority || "normal"]);
      const removeByName = (toRemove) => {
        let isRemoved = false;
        const filterCb = (entry) => {
          const aliases = getAllAliases(entry.name, entry.aliases);
          if (aliases.includes(toRemove)) {
            isRemoved = true;
            for (const alias of aliases) {
              entriesNameSet.delete(alias);
            }
            return false;
          }
          return true;
        };
        absoluteEntries = absoluteEntries.filter(filterCb);
        relativeEntries = relativeEntries.filter(filterCb);
        return isRemoved;
      };
      const removeByReference = (toRemove) => {
        let isRemoved = false;
        const filterCb = (entry) => {
          if (entry.middleware === toRemove) {
            isRemoved = true;
            for (const alias of getAllAliases(entry.name, entry.aliases)) {
              entriesNameSet.delete(alias);
            }
            return false;
          }
          return true;
        };
        absoluteEntries = absoluteEntries.filter(filterCb);
        relativeEntries = relativeEntries.filter(filterCb);
        return isRemoved;
      };
      const cloneTo = (toStack) => {
        absoluteEntries.forEach((entry) => {
          toStack.add(entry.middleware, { ...entry });
        });
        relativeEntries.forEach((entry) => {
          toStack.addRelativeTo(entry.middleware, { ...entry });
        });
        toStack.identifyOnResolve?.(stack.identifyOnResolve());
        return toStack;
      };
      const expandRelativeMiddlewareList = (from) => {
        const expandedMiddlewareList = [];
        from.before.forEach((entry) => {
          if (entry.before.length === 0 && entry.after.length === 0) {
            expandedMiddlewareList.push(entry);
          } else {
            expandedMiddlewareList.push(...expandRelativeMiddlewareList(entry));
          }
        });
        expandedMiddlewareList.push(from);
        from.after.reverse().forEach((entry) => {
          if (entry.before.length === 0 && entry.after.length === 0) {
            expandedMiddlewareList.push(entry);
          } else {
            expandedMiddlewareList.push(...expandRelativeMiddlewareList(entry));
          }
        });
        return expandedMiddlewareList;
      };
      const getMiddlewareList = (debug = false) => {
        const normalizedAbsoluteEntries = [];
        const normalizedRelativeEntries = [];
        const normalizedEntriesNameMap = {};
        absoluteEntries.forEach((entry) => {
          const normalizedEntry = {
            ...entry,
            before: [],
            after: []
          };
          for (const alias of getAllAliases(normalizedEntry.name, normalizedEntry.aliases)) {
            normalizedEntriesNameMap[alias] = normalizedEntry;
          }
          normalizedAbsoluteEntries.push(normalizedEntry);
        });
        relativeEntries.forEach((entry) => {
          const normalizedEntry = {
            ...entry,
            before: [],
            after: []
          };
          for (const alias of getAllAliases(normalizedEntry.name, normalizedEntry.aliases)) {
            normalizedEntriesNameMap[alias] = normalizedEntry;
          }
          normalizedRelativeEntries.push(normalizedEntry);
        });
        normalizedRelativeEntries.forEach((entry) => {
          if (entry.toMiddleware) {
            const toMiddleware = normalizedEntriesNameMap[entry.toMiddleware];
            if (toMiddleware === void 0) {
              if (debug) {
                return;
              }
              throw new Error(`${entry.toMiddleware} is not found when adding ${getMiddlewareNameWithAliases(entry.name, entry.aliases)} middleware ${entry.relation} ${entry.toMiddleware}`);
            }
            if (entry.relation === "after") {
              toMiddleware.after.push(entry);
            }
            if (entry.relation === "before") {
              toMiddleware.before.push(entry);
            }
          }
        });
        const mainChain = sort(normalizedAbsoluteEntries).map(expandRelativeMiddlewareList).reduce((wholeList, expandedMiddlewareList) => {
          wholeList.push(...expandedMiddlewareList);
          return wholeList;
        }, []);
        return mainChain;
      };
      const stack = {
        add: (middleware, options = {}) => {
          const { name, override, aliases: _aliases } = options;
          const entry = {
            step: "initialize",
            priority: "normal",
            middleware,
            ...options
          };
          const aliases = getAllAliases(name, _aliases);
          if (aliases.length > 0) {
            if (aliases.some((alias) => entriesNameSet.has(alias))) {
              if (!override)
                throw new Error(`Duplicate middleware name '${getMiddlewareNameWithAliases(name, _aliases)}'`);
              for (const alias of aliases) {
                const toOverrideIndex = absoluteEntries.findIndex((entry2) => entry2.name === alias || entry2.aliases?.some((a6) => a6 === alias));
                if (toOverrideIndex === -1) {
                  continue;
                }
                const toOverride = absoluteEntries[toOverrideIndex];
                if (toOverride.step !== entry.step || entry.priority !== toOverride.priority) {
                  throw new Error(`"${getMiddlewareNameWithAliases(toOverride.name, toOverride.aliases)}" middleware with ${toOverride.priority} priority in ${toOverride.step} step cannot be overridden by "${getMiddlewareNameWithAliases(name, _aliases)}" middleware with ${entry.priority} priority in ${entry.step} step.`);
                }
                absoluteEntries.splice(toOverrideIndex, 1);
              }
            }
            for (const alias of aliases) {
              entriesNameSet.add(alias);
            }
          }
          absoluteEntries.push(entry);
        },
        addRelativeTo: (middleware, options) => {
          const { name, override, aliases: _aliases } = options;
          const entry = {
            middleware,
            ...options
          };
          const aliases = getAllAliases(name, _aliases);
          if (aliases.length > 0) {
            if (aliases.some((alias) => entriesNameSet.has(alias))) {
              if (!override)
                throw new Error(`Duplicate middleware name '${getMiddlewareNameWithAliases(name, _aliases)}'`);
              for (const alias of aliases) {
                const toOverrideIndex = relativeEntries.findIndex((entry2) => entry2.name === alias || entry2.aliases?.some((a6) => a6 === alias));
                if (toOverrideIndex === -1) {
                  continue;
                }
                const toOverride = relativeEntries[toOverrideIndex];
                if (toOverride.toMiddleware !== entry.toMiddleware || toOverride.relation !== entry.relation) {
                  throw new Error(`"${getMiddlewareNameWithAliases(toOverride.name, toOverride.aliases)}" middleware ${toOverride.relation} "${toOverride.toMiddleware}" middleware cannot be overridden by "${getMiddlewareNameWithAliases(name, _aliases)}" middleware ${entry.relation} "${entry.toMiddleware}" middleware.`);
                }
                relativeEntries.splice(toOverrideIndex, 1);
              }
            }
            for (const alias of aliases) {
              entriesNameSet.add(alias);
            }
          }
          relativeEntries.push(entry);
        },
        clone: () => cloneTo(constructStack()),
        use: (plugin) => {
          plugin.applyToStack(stack);
        },
        remove: (toRemove) => {
          if (typeof toRemove === "string")
            return removeByName(toRemove);
          else
            return removeByReference(toRemove);
        },
        removeByTag: (toRemove) => {
          let isRemoved = false;
          const filterCb = (entry) => {
            const { tags, name, aliases: _aliases } = entry;
            if (tags && tags.includes(toRemove)) {
              const aliases = getAllAliases(name, _aliases);
              for (const alias of aliases) {
                entriesNameSet.delete(alias);
              }
              isRemoved = true;
              return false;
            }
            return true;
          };
          absoluteEntries = absoluteEntries.filter(filterCb);
          relativeEntries = relativeEntries.filter(filterCb);
          return isRemoved;
        },
        concat: (from) => {
          const cloned = cloneTo(constructStack());
          cloned.use(from);
          cloned.identifyOnResolve(identifyOnResolve || cloned.identifyOnResolve() || (from.identifyOnResolve?.() ?? false));
          return cloned;
        },
        applyToStack: cloneTo,
        identify: () => {
          return getMiddlewareList(true).map((mw) => {
            const step = mw.step ?? mw.relation + " " + mw.toMiddleware;
            return getMiddlewareNameWithAliases(mw.name, mw.aliases) + " - " + step;
          });
        },
        identifyOnResolve(toggle) {
          if (typeof toggle === "boolean")
            identifyOnResolve = toggle;
          return identifyOnResolve;
        },
        resolve: (handler2, context) => {
          for (const middleware of getMiddlewareList().map((entry) => entry.middleware).reverse()) {
            handler2 = middleware(handler2, context);
          }
          if (identifyOnResolve) {
            console.log(stack.identify());
          }
          return handler2;
        }
      };
      return stack;
    };
    stepWeights = {
      initialize: 5,
      serialize: 4,
      build: 3,
      finalizeRequest: 2,
      deserialize: 1
    };
    priorityWeights = {
      high: 3,
      normal: 2,
      low: 1
    };
  }
});

// node_modules/@smithy/middleware-stack/dist-es/index.js
var init_dist_es26 = __esm({
  "node_modules/@smithy/middleware-stack/dist-es/index.js"() {
    init_MiddlewareStack();
  }
});

// node_modules/@smithy/smithy-client/dist-es/client.js
var Client;
var init_client3 = __esm({
  "node_modules/@smithy/smithy-client/dist-es/client.js"() {
    init_dist_es26();
    Client = class {
      config;
      middlewareStack = constructStack();
      initConfig;
      handlers;
      constructor(config) {
        this.config = config;
        const { protocol, protocolSettings } = config;
        if (protocolSettings) {
          if (typeof protocol === "function") {
            config.protocol = new protocol(protocolSettings);
          }
        }
      }
      send(command, optionsOrCb, cb) {
        const options = typeof optionsOrCb !== "function" ? optionsOrCb : void 0;
        const callback = typeof optionsOrCb === "function" ? optionsOrCb : cb;
        const useHandlerCache = options === void 0 && this.config.cacheMiddleware === true;
        let handler2;
        if (useHandlerCache) {
          if (!this.handlers) {
            this.handlers = /* @__PURE__ */ new WeakMap();
          }
          const handlers = this.handlers;
          if (handlers.has(command.constructor)) {
            handler2 = handlers.get(command.constructor);
          } else {
            handler2 = command.resolveMiddleware(this.middlewareStack, this.config, options);
            handlers.set(command.constructor, handler2);
          }
        } else {
          delete this.handlers;
          handler2 = command.resolveMiddleware(this.middlewareStack, this.config, options);
        }
        if (callback) {
          handler2(command).then((result) => callback(null, result.output), (err) => callback(err)).catch(() => {
          });
        } else {
          return handler2(command).then((result) => result.output);
        }
      }
      destroy() {
        this.config?.requestHandler?.destroy?.();
        delete this.handlers;
      }
    };
  }
});

// node_modules/@smithy/smithy-client/dist-es/collect-stream-body.js
var init_collect_stream_body2 = __esm({
  "node_modules/@smithy/smithy-client/dist-es/collect-stream-body.js"() {
    init_protocols();
  }
});

// node_modules/@smithy/smithy-client/dist-es/schemaLogFilter.js
function schemaLogFilter(schema, data) {
  if (data == null) {
    return data;
  }
  const ns = NormalizedSchema.of(schema);
  if (ns.getMergedTraits().sensitive) {
    return SENSITIVE_STRING;
  }
  if (ns.isListSchema()) {
    const isSensitive = !!ns.getValueSchema().getMergedTraits().sensitive;
    if (isSensitive) {
      return SENSITIVE_STRING;
    }
  } else if (ns.isMapSchema()) {
    const isSensitive = !!ns.getKeySchema().getMergedTraits().sensitive || !!ns.getValueSchema().getMergedTraits().sensitive;
    if (isSensitive) {
      return SENSITIVE_STRING;
    }
  } else if (ns.isStructSchema() && typeof data === "object") {
    const object = data;
    const newObject = {};
    for (const [member2, memberNs] of ns.structIterator()) {
      if (object[member2] != null) {
        newObject[member2] = schemaLogFilter(memberNs, object[member2]);
      }
    }
    return newObject;
  }
  return data;
}
var SENSITIVE_STRING;
var init_schemaLogFilter = __esm({
  "node_modules/@smithy/smithy-client/dist-es/schemaLogFilter.js"() {
    init_schema2();
    SENSITIVE_STRING = "***SensitiveInformation***";
  }
});

// node_modules/@smithy/smithy-client/dist-es/command.js
var Command, ClassBuilder;
var init_command2 = __esm({
  "node_modules/@smithy/smithy-client/dist-es/command.js"() {
    init_dist_es26();
    init_dist_es();
    init_schemaLogFilter();
    Command = class {
      middlewareStack = constructStack();
      schema;
      static classBuilder() {
        return new ClassBuilder();
      }
      resolveMiddlewareWithContext(clientStack, configuration, options, { middlewareFn, clientName, commandName, inputFilterSensitiveLog, outputFilterSensitiveLog, smithyContext, additionalContext, CommandCtor }) {
        for (const mw of middlewareFn.bind(this)(CommandCtor, clientStack, configuration, options)) {
          this.middlewareStack.use(mw);
        }
        const stack = clientStack.concat(this.middlewareStack);
        const { logger: logger2 } = configuration;
        const handlerExecutionContext = {
          logger: logger2,
          clientName,
          commandName,
          inputFilterSensitiveLog,
          outputFilterSensitiveLog,
          [SMITHY_CONTEXT_KEY]: {
            commandInstance: this,
            ...smithyContext
          },
          ...additionalContext
        };
        const { requestHandler } = configuration;
        return stack.resolve((request2) => requestHandler.handle(request2.request, options || {}), handlerExecutionContext);
      }
    };
    ClassBuilder = class {
      _init = () => {
      };
      _ep = {};
      _middlewareFn = () => [];
      _commandName = "";
      _clientName = "";
      _additionalContext = {};
      _smithyContext = {};
      _inputFilterSensitiveLog = void 0;
      _outputFilterSensitiveLog = void 0;
      _serializer = null;
      _deserializer = null;
      _operationSchema;
      init(cb) {
        this._init = cb;
      }
      ep(endpointParameterInstructions) {
        this._ep = endpointParameterInstructions;
        return this;
      }
      m(middlewareSupplier) {
        this._middlewareFn = middlewareSupplier;
        return this;
      }
      s(service, operation2, smithyContext = {}) {
        this._smithyContext = {
          service,
          operation: operation2,
          ...smithyContext
        };
        return this;
      }
      c(additionalContext = {}) {
        this._additionalContext = additionalContext;
        return this;
      }
      n(clientName, commandName) {
        this._clientName = clientName;
        this._commandName = commandName;
        return this;
      }
      f(inputFilter = (_) => _, outputFilter = (_) => _) {
        this._inputFilterSensitiveLog = inputFilter;
        this._outputFilterSensitiveLog = outputFilter;
        return this;
      }
      ser(serializer) {
        this._serializer = serializer;
        return this;
      }
      de(deserializer) {
        this._deserializer = deserializer;
        return this;
      }
      sc(operation2) {
        this._operationSchema = operation2;
        this._smithyContext.operationSchema = operation2;
        return this;
      }
      build() {
        const closure = this;
        let CommandRef;
        return CommandRef = class extends Command {
          input;
          static getEndpointParameterInstructions() {
            return closure._ep;
          }
          constructor(...[input]) {
            super();
            this.input = input ?? {};
            closure._init(this);
            this.schema = closure._operationSchema;
          }
          resolveMiddleware(stack, configuration, options) {
            const op = closure._operationSchema;
            const input = op?.[4] ?? op?.input;
            const output = op?.[5] ?? op?.output;
            return this.resolveMiddlewareWithContext(stack, configuration, options, {
              CommandCtor: CommandRef,
              middlewareFn: closure._middlewareFn,
              clientName: closure._clientName,
              commandName: closure._commandName,
              inputFilterSensitiveLog: closure._inputFilterSensitiveLog ?? (op ? schemaLogFilter.bind(null, input) : (_) => _),
              outputFilterSensitiveLog: closure._outputFilterSensitiveLog ?? (op ? schemaLogFilter.bind(null, output) : (_) => _),
              smithyContext: closure._smithyContext,
              additionalContext: closure._additionalContext
            });
          }
          serialize = closure._serializer;
          deserialize = closure._deserializer;
        };
      }
    };
  }
});

// node_modules/@smithy/smithy-client/dist-es/constants.js
var init_constants3 = __esm({
  "node_modules/@smithy/smithy-client/dist-es/constants.js"() {
  }
});

// node_modules/@smithy/smithy-client/dist-es/create-aggregated-client.js
var createAggregatedClient;
var init_create_aggregated_client = __esm({
  "node_modules/@smithy/smithy-client/dist-es/create-aggregated-client.js"() {
    createAggregatedClient = (commands5, Client2) => {
      for (const command of Object.keys(commands5)) {
        const CommandCtor = commands5[command];
        const methodImpl = async function(args, optionsOrCb, cb) {
          const command2 = new CommandCtor(args);
          if (typeof optionsOrCb === "function") {
            this.send(command2, optionsOrCb);
          } else if (typeof cb === "function") {
            if (typeof optionsOrCb !== "object")
              throw new Error(`Expected http options but got ${typeof optionsOrCb}`);
            this.send(command2, optionsOrCb || {}, cb);
          } else {
            return this.send(command2, optionsOrCb);
          }
        };
        const methodName = (command[0].toLowerCase() + command.slice(1)).replace(/Command$/, "");
        Client2.prototype[methodName] = methodImpl;
      }
    };
  }
});

// node_modules/@smithy/smithy-client/dist-es/exceptions.js
var ServiceException, decorateServiceException;
var init_exceptions = __esm({
  "node_modules/@smithy/smithy-client/dist-es/exceptions.js"() {
    ServiceException = class _ServiceException extends Error {
      $fault;
      $response;
      $retryable;
      $metadata;
      constructor(options) {
        super(options.message);
        Object.setPrototypeOf(this, Object.getPrototypeOf(this).constructor.prototype);
        this.name = options.name;
        this.$fault = options.$fault;
        this.$metadata = options.$metadata;
      }
      static isInstance(value) {
        if (!value)
          return false;
        const candidate = value;
        return _ServiceException.prototype.isPrototypeOf(candidate) || Boolean(candidate.$fault) && Boolean(candidate.$metadata) && (candidate.$fault === "client" || candidate.$fault === "server");
      }
      static [Symbol.hasInstance](instance) {
        if (!instance)
          return false;
        const candidate = instance;
        if (this === _ServiceException) {
          return _ServiceException.isInstance(instance);
        }
        if (_ServiceException.isInstance(instance)) {
          if (candidate.name && this.name) {
            return this.prototype.isPrototypeOf(instance) || candidate.name === this.name;
          }
          return this.prototype.isPrototypeOf(instance);
        }
        return false;
      }
    };
    decorateServiceException = (exception, additions = {}) => {
      Object.entries(additions).filter(([, v7]) => v7 !== void 0).forEach(([k6, v7]) => {
        if (exception[k6] == void 0 || exception[k6] === "") {
          exception[k6] = v7;
        }
      });
      const message = exception.message || exception.Message || "UnknownError";
      exception.message = message;
      delete exception.Message;
      return exception;
    };
  }
});

// node_modules/@smithy/smithy-client/dist-es/default-error-handler.js
var init_default_error_handler = __esm({
  "node_modules/@smithy/smithy-client/dist-es/default-error-handler.js"() {
  }
});

// node_modules/@smithy/smithy-client/dist-es/defaults-mode.js
var loadConfigsForDefaultMode;
var init_defaults_mode = __esm({
  "node_modules/@smithy/smithy-client/dist-es/defaults-mode.js"() {
    loadConfigsForDefaultMode = (mode) => {
      switch (mode) {
        case "standard":
          return {
            retryMode: "standard",
            connectionTimeout: 3100
          };
        case "in-region":
          return {
            retryMode: "standard",
            connectionTimeout: 1100
          };
        case "cross-region":
          return {
            retryMode: "standard",
            connectionTimeout: 3100
          };
        case "mobile":
          return {
            retryMode: "standard",
            connectionTimeout: 3e4
          };
        default:
          return {};
      }
    };
  }
});

// node_modules/@smithy/smithy-client/dist-es/emitWarningIfUnsupportedVersion.js
var warningEmitted, emitWarningIfUnsupportedVersion2;
var init_emitWarningIfUnsupportedVersion2 = __esm({
  "node_modules/@smithy/smithy-client/dist-es/emitWarningIfUnsupportedVersion.js"() {
    warningEmitted = false;
    emitWarningIfUnsupportedVersion2 = (version) => {
      if (version && !warningEmitted && parseInt(version.substring(1, version.indexOf("."))) < 16) {
        warningEmitted = true;
      }
    };
  }
});

// node_modules/@smithy/smithy-client/dist-es/extended-encode-uri-component.js
var init_extended_encode_uri_component2 = __esm({
  "node_modules/@smithy/smithy-client/dist-es/extended-encode-uri-component.js"() {
  }
});

// node_modules/@smithy/smithy-client/dist-es/extensions/checksum.js
var getChecksumConfiguration, resolveChecksumRuntimeConfig;
var init_checksum3 = __esm({
  "node_modules/@smithy/smithy-client/dist-es/extensions/checksum.js"() {
    init_dist_es();
    getChecksumConfiguration = (runtimeConfig) => {
      const checksumAlgorithms = [];
      for (const id in AlgorithmId) {
        const algorithmId = AlgorithmId[id];
        if (runtimeConfig[algorithmId] === void 0) {
          continue;
        }
        checksumAlgorithms.push({
          algorithmId: () => algorithmId,
          checksumConstructor: () => runtimeConfig[algorithmId]
        });
      }
      return {
        addChecksumAlgorithm(algo) {
          checksumAlgorithms.push(algo);
        },
        checksumAlgorithms() {
          return checksumAlgorithms;
        }
      };
    };
    resolveChecksumRuntimeConfig = (clientConfig) => {
      const runtimeConfig = {};
      clientConfig.checksumAlgorithms().forEach((checksumAlgorithm) => {
        runtimeConfig[checksumAlgorithm.algorithmId()] = checksumAlgorithm.checksumConstructor();
      });
      return runtimeConfig;
    };
  }
});

// node_modules/@smithy/smithy-client/dist-es/extensions/retry.js
var getRetryConfiguration, resolveRetryRuntimeConfig;
var init_retry2 = __esm({
  "node_modules/@smithy/smithy-client/dist-es/extensions/retry.js"() {
    getRetryConfiguration = (runtimeConfig) => {
      return {
        setRetryStrategy(retryStrategy) {
          runtimeConfig.retryStrategy = retryStrategy;
        },
        retryStrategy() {
          return runtimeConfig.retryStrategy;
        }
      };
    };
    resolveRetryRuntimeConfig = (retryStrategyConfiguration) => {
      const runtimeConfig = {};
      runtimeConfig.retryStrategy = retryStrategyConfiguration.retryStrategy();
      return runtimeConfig;
    };
  }
});

// node_modules/@smithy/smithy-client/dist-es/extensions/defaultExtensionConfiguration.js
var getDefaultExtensionConfiguration, resolveDefaultRuntimeConfig;
var init_defaultExtensionConfiguration2 = __esm({
  "node_modules/@smithy/smithy-client/dist-es/extensions/defaultExtensionConfiguration.js"() {
    init_checksum3();
    init_retry2();
    getDefaultExtensionConfiguration = (runtimeConfig) => {
      return Object.assign(getChecksumConfiguration(runtimeConfig), getRetryConfiguration(runtimeConfig));
    };
    resolveDefaultRuntimeConfig = (config) => {
      return Object.assign(resolveChecksumRuntimeConfig(config), resolveRetryRuntimeConfig(config));
    };
  }
});

// node_modules/@smithy/smithy-client/dist-es/extensions/index.js
var init_extensions3 = __esm({
  "node_modules/@smithy/smithy-client/dist-es/extensions/index.js"() {
    init_defaultExtensionConfiguration2();
  }
});

// node_modules/@smithy/smithy-client/dist-es/get-array-if-single-item.js
var init_get_array_if_single_item = __esm({
  "node_modules/@smithy/smithy-client/dist-es/get-array-if-single-item.js"() {
  }
});

// node_modules/@smithy/smithy-client/dist-es/get-value-from-text-node.js
var getValueFromTextNode;
var init_get_value_from_text_node = __esm({
  "node_modules/@smithy/smithy-client/dist-es/get-value-from-text-node.js"() {
    getValueFromTextNode = (obj) => {
      const textNodeName = "#text";
      for (const key in obj) {
        if (obj.hasOwnProperty(key) && obj[key][textNodeName] !== void 0) {
          obj[key] = obj[key][textNodeName];
        } else if (typeof obj[key] === "object" && obj[key] !== null) {
          obj[key] = getValueFromTextNode(obj[key]);
        }
      }
      return obj;
    };
  }
});

// node_modules/@smithy/smithy-client/dist-es/is-serializable-header-value.js
var init_is_serializable_header_value = __esm({
  "node_modules/@smithy/smithy-client/dist-es/is-serializable-header-value.js"() {
  }
});

// node_modules/@smithy/smithy-client/dist-es/NoOpLogger.js
var NoOpLogger;
var init_NoOpLogger = __esm({
  "node_modules/@smithy/smithy-client/dist-es/NoOpLogger.js"() {
    NoOpLogger = class {
      trace() {
      }
      debug() {
      }
      info() {
      }
      warn() {
      }
      error() {
      }
    };
  }
});

// node_modules/@smithy/smithy-client/dist-es/object-mapping.js
var init_object_mapping = __esm({
  "node_modules/@smithy/smithy-client/dist-es/object-mapping.js"() {
  }
});

// node_modules/@smithy/smithy-client/dist-es/resolve-path.js
var init_resolve_path2 = __esm({
  "node_modules/@smithy/smithy-client/dist-es/resolve-path.js"() {
  }
});

// node_modules/@smithy/smithy-client/dist-es/ser-utils.js
var init_ser_utils = __esm({
  "node_modules/@smithy/smithy-client/dist-es/ser-utils.js"() {
  }
});

// node_modules/@smithy/smithy-client/dist-es/serde-json.js
var init_serde_json = __esm({
  "node_modules/@smithy/smithy-client/dist-es/serde-json.js"() {
  }
});

// node_modules/@smithy/smithy-client/dist-es/index.js
var init_dist_es27 = __esm({
  "node_modules/@smithy/smithy-client/dist-es/index.js"() {
    init_client3();
    init_collect_stream_body2();
    init_command2();
    init_constants3();
    init_create_aggregated_client();
    init_default_error_handler();
    init_defaults_mode();
    init_emitWarningIfUnsupportedVersion2();
    init_exceptions();
    init_extended_encode_uri_component2();
    init_extensions3();
    init_get_array_if_single_item();
    init_get_value_from_text_node();
    init_is_serializable_header_value();
    init_NoOpLogger();
    init_object_mapping();
    init_resolve_path2();
    init_ser_utils();
    init_serde_json();
    init_serde2();
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/ProtocolLib.js
var ProtocolLib;
var init_ProtocolLib = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/protocols/ProtocolLib.js"() {
    init_schema2();
    init_dist_es27();
    ProtocolLib = class {
      queryCompat;
      constructor(queryCompat = false) {
        this.queryCompat = queryCompat;
      }
      resolveRestContentType(defaultContentType, inputSchema) {
        const members = inputSchema.getMemberSchemas();
        const httpPayloadMember = Object.values(members).find((m6) => {
          return !!m6.getMergedTraits().httpPayload;
        });
        if (httpPayloadMember) {
          const mediaType = httpPayloadMember.getMergedTraits().mediaType;
          if (mediaType) {
            return mediaType;
          } else if (httpPayloadMember.isStringSchema()) {
            return "text/plain";
          } else if (httpPayloadMember.isBlobSchema()) {
            return "application/octet-stream";
          } else {
            return defaultContentType;
          }
        } else if (!inputSchema.isUnitSchema()) {
          const hasBody = Object.values(members).find((m6) => {
            const { httpQuery, httpQueryParams, httpHeader, httpLabel, httpPrefixHeaders } = m6.getMergedTraits();
            const noPrefixHeaders = httpPrefixHeaders === void 0;
            return !httpQuery && !httpQueryParams && !httpHeader && !httpLabel && noPrefixHeaders;
          });
          if (hasBody) {
            return defaultContentType;
          }
        }
      }
      async getErrorSchemaOrThrowBaseException(errorIdentifier, defaultNamespace, response, dataObject, metadata, getErrorSchema) {
        let namespace = defaultNamespace;
        let errorName = errorIdentifier;
        if (errorIdentifier.includes("#")) {
          [namespace, errorName] = errorIdentifier.split("#");
        }
        const errorMetadata = {
          $metadata: metadata,
          $fault: response.statusCode < 500 ? "client" : "server"
        };
        const registry = TypeRegistry.for(namespace);
        try {
          const errorSchema = getErrorSchema?.(registry, errorName) ?? registry.getSchema(errorIdentifier);
          return { errorSchema, errorMetadata };
        } catch (e6) {
          dataObject.message = dataObject.message ?? dataObject.Message ?? "UnknownError";
          const synthetic = TypeRegistry.for("smithy.ts.sdk.synthetic." + namespace);
          const baseExceptionSchema = synthetic.getBaseException();
          if (baseExceptionSchema) {
            const ErrorCtor = synthetic.getErrorCtor(baseExceptionSchema) ?? Error;
            throw this.decorateServiceException(Object.assign(new ErrorCtor({ name: errorName }), errorMetadata), dataObject);
          }
          throw this.decorateServiceException(Object.assign(new Error(errorName), errorMetadata), dataObject);
        }
      }
      decorateServiceException(exception, additions = {}) {
        if (this.queryCompat) {
          const msg = exception.Message ?? additions.Message;
          const error = decorateServiceException(exception, additions);
          if (msg) {
            error.message = msg;
          }
          error.Error = {
            ...error.Error,
            Type: error.Error.Type,
            Code: error.Error.Code,
            Message: error.Error.message ?? error.Error.Message ?? msg
          };
          const reqId = error.$metadata.requestId;
          if (reqId) {
            error.RequestId = reqId;
          }
          return error;
        }
        return decorateServiceException(exception, additions);
      }
      setQueryCompatError(output, response) {
        const queryErrorHeader = response.headers?.["x-amzn-query-error"];
        if (output !== void 0 && queryErrorHeader != null) {
          const [Code, Type] = queryErrorHeader.split(";");
          const entries = Object.entries(output);
          const Error2 = {
            Code,
            Type
          };
          Object.assign(output, Error2);
          for (const [k6, v7] of entries) {
            Error2[k6 === "message" ? "Message" : k6] = v7;
          }
          delete Error2.__type;
          output.Error = Error2;
        }
      }
      queryCompatOutput(queryCompatErrorData, errorData) {
        if (queryCompatErrorData.Error) {
          errorData.Error = queryCompatErrorData.Error;
        }
        if (queryCompatErrorData.Type) {
          errorData.Type = queryCompatErrorData.Type;
        }
        if (queryCompatErrorData.Code) {
          errorData.Code = queryCompatErrorData.Code;
        }
      }
      findQueryCompatibleError(registry, errorName) {
        try {
          return registry.getSchema(errorName);
        } catch (e6) {
          return registry.find((schema) => NormalizedSchema.of(schema).getMergedTraits().awsQueryError?.[0] === errorName);
        }
      }
    };
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/cbor/AwsSmithyRpcV2CborProtocol.js
var init_AwsSmithyRpcV2CborProtocol = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/protocols/cbor/AwsSmithyRpcV2CborProtocol.js"() {
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/coercing-serializers.js
var init_coercing_serializers = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/protocols/coercing-serializers.js"() {
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/ConfigurableSerdeContext.js
var SerdeContextConfig;
var init_ConfigurableSerdeContext = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/protocols/ConfigurableSerdeContext.js"() {
    SerdeContextConfig = class {
      serdeContext;
      setSerdeContext(serdeContext) {
        this.serdeContext = serdeContext;
      }
    };
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/structIterator.js
function* serializingStructIterator(ns, sourceObject) {
  if (ns.isUnitSchema()) {
    return;
  }
  const struct = ns.getSchema();
  for (let i6 = 0; i6 < struct[4].length; ++i6) {
    const key = struct[4][i6];
    const memberSchema = struct[5][i6];
    const memberNs = new NormalizedSchema([memberSchema, 0], key);
    if (!(key in sourceObject) && !memberNs.isIdempotencyToken()) {
      continue;
    }
    yield [key, memberNs];
  }
}
function* deserializingStructIterator(ns, sourceObject, nameTrait) {
  if (ns.isUnitSchema()) {
    return;
  }
  const struct = ns.getSchema();
  let keysRemaining = Object.keys(sourceObject).filter((k6) => k6 !== "__type").length;
  for (let i6 = 0; i6 < struct[4].length; ++i6) {
    if (keysRemaining === 0) {
      break;
    }
    const key = struct[4][i6];
    const memberSchema = struct[5][i6];
    const memberNs = new NormalizedSchema([memberSchema, 0], key);
    let serializationKey = key;
    if (nameTrait) {
      serializationKey = memberNs.getMergedTraits()[nameTrait] ?? key;
    }
    if (!(serializationKey in sourceObject)) {
      continue;
    }
    yield [key, memberNs];
    keysRemaining -= 1;
  }
}
var init_structIterator = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/protocols/structIterator.js"() {
    init_schema2();
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/UnionSerde.js
var UnionSerde;
var init_UnionSerde = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/protocols/UnionSerde.js"() {
    UnionSerde = class {
      from;
      to;
      keys;
      constructor(from, to) {
        this.from = from;
        this.to = to;
        this.keys = new Set(Object.keys(this.from).filter((k6) => k6 !== "__type"));
      }
      mark(key) {
        this.keys.delete(key);
      }
      hasUnknown() {
        return this.keys.size === 1 && Object.keys(this.to).length === 0;
      }
      writeUnknown() {
        if (this.hasUnknown()) {
          const k6 = this.keys.values().next().value;
          const v7 = this.from[k6];
          this.to.$unknown = [k6, v7];
        }
      }
    };
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/jsonReviver.js
function jsonReviver(key, value, context) {
  if (context?.source) {
    const numericString = context.source;
    if (typeof value === "number") {
      if (value > Number.MAX_SAFE_INTEGER || value < Number.MIN_SAFE_INTEGER || numericString !== String(value)) {
        const isFractional = numericString.includes(".");
        if (isFractional) {
          return new NumericValue(numericString, "bigDecimal");
        } else {
          return BigInt(numericString);
        }
      }
    }
  }
  return value;
}
var init_jsonReviver = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/jsonReviver.js"() {
    init_serde2();
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/common.js
var collectBodyString;
var init_common = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/protocols/common.js"() {
    init_dist_es27();
    init_dist_es10();
    collectBodyString = (streamBody, context) => collectBody(streamBody, context).then((body) => (context?.utf8Encoder ?? toUtf8)(body));
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/parseJsonBody.js
var parseJsonBody, loadRestJsonErrorCode;
var init_parseJsonBody = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/parseJsonBody.js"() {
    init_common();
    parseJsonBody = (streamBody, context) => collectBodyString(streamBody, context).then((encoded) => {
      if (encoded.length) {
        try {
          return JSON.parse(encoded);
        } catch (e6) {
          if (e6?.name === "SyntaxError") {
            Object.defineProperty(e6, "$responseBodyText", {
              value: encoded
            });
          }
          throw e6;
        }
      }
      return {};
    });
    loadRestJsonErrorCode = (output, data) => {
      const findKey = (object, key) => Object.keys(object).find((k6) => k6.toLowerCase() === key.toLowerCase());
      const sanitizeErrorCode = (rawValue) => {
        let cleanValue = rawValue;
        if (typeof cleanValue === "number") {
          cleanValue = cleanValue.toString();
        }
        if (cleanValue.indexOf(",") >= 0) {
          cleanValue = cleanValue.split(",")[0];
        }
        if (cleanValue.indexOf(":") >= 0) {
          cleanValue = cleanValue.split(":")[0];
        }
        if (cleanValue.indexOf("#") >= 0) {
          cleanValue = cleanValue.split("#")[1];
        }
        return cleanValue;
      };
      const headerKey = findKey(output.headers, "x-amzn-errortype");
      if (headerKey !== void 0) {
        return sanitizeErrorCode(output.headers[headerKey]);
      }
      if (data && typeof data === "object") {
        const codeKey = findKey(data, "code");
        if (codeKey && data[codeKey] !== void 0) {
          return sanitizeErrorCode(data[codeKey]);
        }
        if (data["__type"] !== void 0) {
          return sanitizeErrorCode(data["__type"]);
        }
      }
    };
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/JsonShapeDeserializer.js
var JsonShapeDeserializer;
var init_JsonShapeDeserializer = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/JsonShapeDeserializer.js"() {
    init_protocols();
    init_schema2();
    init_serde2();
    init_dist_es11();
    init_ConfigurableSerdeContext();
    init_structIterator();
    init_UnionSerde();
    init_jsonReviver();
    init_parseJsonBody();
    JsonShapeDeserializer = class extends SerdeContextConfig {
      settings;
      constructor(settings) {
        super();
        this.settings = settings;
      }
      async read(schema, data) {
        return this._read(schema, typeof data === "string" ? JSON.parse(data, jsonReviver) : await parseJsonBody(data, this.serdeContext));
      }
      readObject(schema, data) {
        return this._read(schema, data);
      }
      _read(schema, value) {
        const isObject = value !== null && typeof value === "object";
        const ns = NormalizedSchema.of(schema);
        if (isObject) {
          if (ns.isStructSchema()) {
            const union = ns.isUnionSchema();
            const out = {};
            let unionSerde;
            if (union) {
              unionSerde = new UnionSerde(value, out);
            }
            for (const [memberName, memberSchema] of deserializingStructIterator(ns, value, this.settings.jsonName ? "jsonName" : false)) {
              const fromKey = this.settings.jsonName ? memberSchema.getMergedTraits().jsonName ?? memberName : memberName;
              if (union) {
                unionSerde.mark(fromKey);
              }
              if (value[fromKey] != null) {
                out[memberName] = this._read(memberSchema, value[fromKey]);
              }
            }
            if (union) {
              unionSerde.writeUnknown();
            }
            return out;
          }
          if (Array.isArray(value) && ns.isListSchema()) {
            const listMember = ns.getValueSchema();
            const out = [];
            const sparse = !!ns.getMergedTraits().sparse;
            for (const item of value) {
              if (sparse || item != null) {
                out.push(this._read(listMember, item));
              }
            }
            return out;
          }
          if (ns.isMapSchema()) {
            const mapMember = ns.getValueSchema();
            const out = {};
            const sparse = !!ns.getMergedTraits().sparse;
            for (const [_k, _v2] of Object.entries(value)) {
              if (sparse || _v2 != null) {
                out[_k] = this._read(mapMember, _v2);
              }
            }
            return out;
          }
        }
        if (ns.isBlobSchema() && typeof value === "string") {
          return fromBase64(value);
        }
        const mediaType = ns.getMergedTraits().mediaType;
        if (ns.isStringSchema() && typeof value === "string" && mediaType) {
          const isJson = mediaType === "application/json" || mediaType.endsWith("+json");
          if (isJson) {
            return LazyJsonString.from(value);
          }
          return value;
        }
        if (ns.isTimestampSchema() && value != null) {
          const format2 = determineTimestampFormat(ns, this.settings);
          switch (format2) {
            case 5:
              return parseRfc3339DateTimeWithOffset(value);
            case 6:
              return parseRfc7231DateTime(value);
            case 7:
              return parseEpochTimestamp(value);
            default:
              console.warn("Missing timestamp format, parsing value with Date constructor:", value);
              return new Date(value);
          }
        }
        if (ns.isBigIntegerSchema() && (typeof value === "number" || typeof value === "string")) {
          return BigInt(value);
        }
        if (ns.isBigDecimalSchema() && value != void 0) {
          if (value instanceof NumericValue) {
            return value;
          }
          const untyped = value;
          if (untyped.type === "bigDecimal" && "string" in untyped) {
            return new NumericValue(untyped.string, untyped.type);
          }
          return new NumericValue(String(value), "bigDecimal");
        }
        if (ns.isNumericSchema() && typeof value === "string") {
          switch (value) {
            case "Infinity":
              return Infinity;
            case "-Infinity":
              return -Infinity;
            case "NaN":
              return NaN;
          }
          return value;
        }
        if (ns.isDocumentSchema()) {
          if (isObject) {
            const out = Array.isArray(value) ? [] : {};
            for (const [k6, v7] of Object.entries(value)) {
              if (v7 instanceof NumericValue) {
                out[k6] = v7;
              } else {
                out[k6] = this._read(ns, v7);
              }
            }
            return out;
          } else {
            return structuredClone(value);
          }
        }
        return value;
      }
    };
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/jsonReplacer.js
var NUMERIC_CONTROL_CHAR, JsonReplacer;
var init_jsonReplacer = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/jsonReplacer.js"() {
    init_serde2();
    NUMERIC_CONTROL_CHAR = String.fromCharCode(925);
    JsonReplacer = class {
      values = /* @__PURE__ */ new Map();
      counter = 0;
      stage = 0;
      createReplacer() {
        if (this.stage === 1) {
          throw new Error("@aws-sdk/core/protocols - JsonReplacer already created.");
        }
        if (this.stage === 2) {
          throw new Error("@aws-sdk/core/protocols - JsonReplacer exhausted.");
        }
        this.stage = 1;
        return (key, value) => {
          if (value instanceof NumericValue) {
            const v7 = `${NUMERIC_CONTROL_CHAR + "nv" + this.counter++}_` + value.string;
            this.values.set(`"${v7}"`, value.string);
            return v7;
          }
          if (typeof value === "bigint") {
            const s6 = value.toString();
            const v7 = `${NUMERIC_CONTROL_CHAR + "b" + this.counter++}_` + s6;
            this.values.set(`"${v7}"`, s6);
            return v7;
          }
          return value;
        };
      }
      replaceInJson(json) {
        if (this.stage === 0) {
          throw new Error("@aws-sdk/core/protocols - JsonReplacer not created yet.");
        }
        if (this.stage === 2) {
          throw new Error("@aws-sdk/core/protocols - JsonReplacer exhausted.");
        }
        this.stage = 2;
        if (this.counter === 0) {
          return json;
        }
        for (const [key, value] of this.values) {
          json = json.replace(key, value);
        }
        return json;
      }
    };
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/JsonShapeSerializer.js
var JsonShapeSerializer;
var init_JsonShapeSerializer = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/JsonShapeSerializer.js"() {
    init_protocols();
    init_schema2();
    init_serde2();
    init_dist_es11();
    init_ConfigurableSerdeContext();
    init_structIterator();
    init_jsonReplacer();
    JsonShapeSerializer = class extends SerdeContextConfig {
      settings;
      buffer;
      useReplacer = false;
      rootSchema;
      constructor(settings) {
        super();
        this.settings = settings;
      }
      write(schema, value) {
        this.rootSchema = NormalizedSchema.of(schema);
        this.buffer = this._write(this.rootSchema, value);
      }
      writeDiscriminatedDocument(schema, value) {
        this.write(schema, value);
        if (typeof this.buffer === "object") {
          this.buffer.__type = NormalizedSchema.of(schema).getName(true);
        }
      }
      flush() {
        const { rootSchema, useReplacer } = this;
        this.rootSchema = void 0;
        this.useReplacer = false;
        if (rootSchema?.isStructSchema() || rootSchema?.isDocumentSchema()) {
          if (!useReplacer) {
            return JSON.stringify(this.buffer);
          }
          const replacer = new JsonReplacer();
          return replacer.replaceInJson(JSON.stringify(this.buffer, replacer.createReplacer(), 0));
        }
        return this.buffer;
      }
      _write(schema, value, container) {
        const isObject = value !== null && typeof value === "object";
        const ns = NormalizedSchema.of(schema);
        if (isObject) {
          if (ns.isStructSchema()) {
            const out = {};
            for (const [memberName, memberSchema] of serializingStructIterator(ns, value)) {
              const serializableValue = this._write(memberSchema, value[memberName], ns);
              if (serializableValue !== void 0) {
                const jsonName = memberSchema.getMergedTraits().jsonName;
                const targetKey = this.settings.jsonName ? jsonName ?? memberName : memberName;
                out[targetKey] = serializableValue;
              }
            }
            if (ns.isUnionSchema() && Object.keys(out).length === 0) {
              const { $unknown } = value;
              if (Array.isArray($unknown)) {
                const [k6, v7] = $unknown;
                out[k6] = this._write(15, v7);
              }
            }
            return out;
          }
          if (Array.isArray(value) && ns.isListSchema()) {
            const listMember = ns.getValueSchema();
            const out = [];
            const sparse = !!ns.getMergedTraits().sparse;
            for (const item of value) {
              if (sparse || item != null) {
                out.push(this._write(listMember, item));
              }
            }
            return out;
          }
          if (ns.isMapSchema()) {
            const mapMember = ns.getValueSchema();
            const out = {};
            const sparse = !!ns.getMergedTraits().sparse;
            for (const [_k, _v2] of Object.entries(value)) {
              if (sparse || _v2 != null) {
                out[_k] = this._write(mapMember, _v2);
              }
            }
            return out;
          }
          if (value instanceof Uint8Array && (ns.isBlobSchema() || ns.isDocumentSchema())) {
            if (ns === this.rootSchema) {
              return value;
            }
            return (this.serdeContext?.base64Encoder ?? toBase64)(value);
          }
          if (value instanceof Date && (ns.isTimestampSchema() || ns.isDocumentSchema())) {
            const format2 = determineTimestampFormat(ns, this.settings);
            switch (format2) {
              case 5:
                return value.toISOString().replace(".000Z", "Z");
              case 6:
                return dateToUtcString(value);
              case 7:
                return value.getTime() / 1e3;
              default:
                console.warn("Missing timestamp format, using epoch seconds", value);
                return value.getTime() / 1e3;
            }
          }
          if (value instanceof NumericValue) {
            this.useReplacer = true;
          }
        }
        if (value === null && container?.isStructSchema()) {
          return void 0;
        }
        if (ns.isStringSchema()) {
          if (typeof value === "undefined" && ns.isIdempotencyToken()) {
            return v4();
          }
          const mediaType = ns.getMergedTraits().mediaType;
          if (value != null && mediaType) {
            const isJson = mediaType === "application/json" || mediaType.endsWith("+json");
            if (isJson) {
              return LazyJsonString.from(value);
            }
          }
          return value;
        }
        if (typeof value === "number" && ns.isNumericSchema()) {
          if (Math.abs(value) === Infinity || isNaN(value)) {
            return String(value);
          }
          return value;
        }
        if (typeof value === "string" && ns.isBlobSchema()) {
          if (ns === this.rootSchema) {
            return value;
          }
          return (this.serdeContext?.base64Encoder ?? toBase64)(value);
        }
        if (typeof value === "bigint") {
          this.useReplacer = true;
        }
        if (ns.isDocumentSchema()) {
          if (isObject) {
            const out = Array.isArray(value) ? [] : {};
            for (const [k6, v7] of Object.entries(value)) {
              if (v7 instanceof NumericValue) {
                this.useReplacer = true;
                out[k6] = v7;
              } else {
                out[k6] = this._write(ns, v7);
              }
            }
            return out;
          } else {
            return structuredClone(value);
          }
        }
        return value;
      }
    };
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/JsonCodec.js
var JsonCodec;
var init_JsonCodec = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/JsonCodec.js"() {
    init_ConfigurableSerdeContext();
    init_JsonShapeDeserializer();
    init_JsonShapeSerializer();
    JsonCodec = class extends SerdeContextConfig {
      settings;
      constructor(settings) {
        super();
        this.settings = settings;
      }
      createSerializer() {
        const serializer = new JsonShapeSerializer(this.settings);
        serializer.setSerdeContext(this.serdeContext);
        return serializer;
      }
      createDeserializer() {
        const deserializer = new JsonShapeDeserializer(this.settings);
        deserializer.setSerdeContext(this.serdeContext);
        return deserializer;
      }
    };
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/AwsJsonRpcProtocol.js
var AwsJsonRpcProtocol;
var init_AwsJsonRpcProtocol = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/AwsJsonRpcProtocol.js"() {
    init_protocols();
    init_schema2();
    init_ProtocolLib();
    init_JsonCodec();
    init_parseJsonBody();
    AwsJsonRpcProtocol = class extends RpcProtocol {
      serializer;
      deserializer;
      serviceTarget;
      codec;
      mixin;
      awsQueryCompatible;
      constructor({ defaultNamespace, serviceTarget, awsQueryCompatible, jsonCodec }) {
        super({
          defaultNamespace
        });
        this.serviceTarget = serviceTarget;
        this.codec = jsonCodec ?? new JsonCodec({
          timestampFormat: {
            useTrait: true,
            default: 7
          },
          jsonName: false
        });
        this.serializer = this.codec.createSerializer();
        this.deserializer = this.codec.createDeserializer();
        this.awsQueryCompatible = !!awsQueryCompatible;
        this.mixin = new ProtocolLib(this.awsQueryCompatible);
      }
      async serializeRequest(operationSchema, input, context) {
        const request2 = await super.serializeRequest(operationSchema, input, context);
        if (!request2.path.endsWith("/")) {
          request2.path += "/";
        }
        Object.assign(request2.headers, {
          "content-type": `application/x-amz-json-${this.getJsonRpcVersion()}`,
          "x-amz-target": `${this.serviceTarget}.${operationSchema.name}`
        });
        if (this.awsQueryCompatible) {
          request2.headers["x-amzn-query-mode"] = "true";
        }
        if (deref(operationSchema.input) === "unit" || !request2.body) {
          request2.body = "{}";
        }
        return request2;
      }
      getPayloadCodec() {
        return this.codec;
      }
      async handleError(operationSchema, context, response, dataObject, metadata) {
        if (this.awsQueryCompatible) {
          this.mixin.setQueryCompatError(dataObject, response);
        }
        const errorIdentifier = loadRestJsonErrorCode(response, dataObject) ?? "Unknown";
        const { errorSchema, errorMetadata } = await this.mixin.getErrorSchemaOrThrowBaseException(errorIdentifier, this.options.defaultNamespace, response, dataObject, metadata, this.awsQueryCompatible ? this.mixin.findQueryCompatibleError : void 0);
        const ns = NormalizedSchema.of(errorSchema);
        const message = dataObject.message ?? dataObject.Message ?? "Unknown";
        const ErrorCtor = TypeRegistry.for(errorSchema[1]).getErrorCtor(errorSchema) ?? Error;
        const exception = new ErrorCtor(message);
        const output = {};
        for (const [name, member2] of ns.structIterator()) {
          if (dataObject[name] != null) {
            output[name] = this.codec.createDeserializer().readObject(member2, dataObject[name]);
          }
        }
        if (this.awsQueryCompatible) {
          this.mixin.queryCompatOutput(dataObject, output);
        }
        throw this.mixin.decorateServiceException(Object.assign(exception, errorMetadata, {
          $fault: ns.getMergedTraits().error,
          message
        }, output), dataObject);
      }
    };
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/AwsJson1_0Protocol.js
var AwsJson1_0Protocol;
var init_AwsJson1_0Protocol = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/AwsJson1_0Protocol.js"() {
    init_AwsJsonRpcProtocol();
    AwsJson1_0Protocol = class extends AwsJsonRpcProtocol {
      constructor({ defaultNamespace, serviceTarget, awsQueryCompatible, jsonCodec }) {
        super({
          defaultNamespace,
          serviceTarget,
          awsQueryCompatible,
          jsonCodec
        });
      }
      getShapeId() {
        return "aws.protocols#awsJson1_0";
      }
      getJsonRpcVersion() {
        return "1.0";
      }
      getDefaultContentType() {
        return "application/x-amz-json-1.0";
      }
    };
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/AwsJson1_1Protocol.js
var init_AwsJson1_1Protocol = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/AwsJson1_1Protocol.js"() {
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/AwsRestJsonProtocol.js
var AwsRestJsonProtocol;
var init_AwsRestJsonProtocol = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/AwsRestJsonProtocol.js"() {
    init_protocols();
    init_schema2();
    init_ProtocolLib();
    init_JsonCodec();
    init_parseJsonBody();
    AwsRestJsonProtocol = class extends HttpBindingProtocol {
      serializer;
      deserializer;
      codec;
      mixin = new ProtocolLib();
      constructor({ defaultNamespace }) {
        super({
          defaultNamespace
        });
        const settings = {
          timestampFormat: {
            useTrait: true,
            default: 7
          },
          httpBindings: true,
          jsonName: true
        };
        this.codec = new JsonCodec(settings);
        this.serializer = new HttpInterceptingShapeSerializer(this.codec.createSerializer(), settings);
        this.deserializer = new HttpInterceptingShapeDeserializer(this.codec.createDeserializer(), settings);
      }
      getShapeId() {
        return "aws.protocols#restJson1";
      }
      getPayloadCodec() {
        return this.codec;
      }
      setSerdeContext(serdeContext) {
        this.codec.setSerdeContext(serdeContext);
        super.setSerdeContext(serdeContext);
      }
      async serializeRequest(operationSchema, input, context) {
        const request2 = await super.serializeRequest(operationSchema, input, context);
        const inputSchema = NormalizedSchema.of(operationSchema.input);
        if (!request2.headers["content-type"]) {
          const contentType = this.mixin.resolveRestContentType(this.getDefaultContentType(), inputSchema);
          if (contentType) {
            request2.headers["content-type"] = contentType;
          }
        }
        if (request2.body == null && request2.headers["content-type"] === this.getDefaultContentType()) {
          request2.body = "{}";
        }
        return request2;
      }
      async deserializeResponse(operationSchema, context, response) {
        const output = await super.deserializeResponse(operationSchema, context, response);
        const outputSchema = NormalizedSchema.of(operationSchema.output);
        for (const [name, member2] of outputSchema.structIterator()) {
          if (member2.getMemberTraits().httpPayload && !(name in output)) {
            output[name] = null;
          }
        }
        return output;
      }
      async handleError(operationSchema, context, response, dataObject, metadata) {
        const errorIdentifier = loadRestJsonErrorCode(response, dataObject) ?? "Unknown";
        const { errorSchema, errorMetadata } = await this.mixin.getErrorSchemaOrThrowBaseException(errorIdentifier, this.options.defaultNamespace, response, dataObject, metadata);
        const ns = NormalizedSchema.of(errorSchema);
        const message = dataObject.message ?? dataObject.Message ?? "Unknown";
        const ErrorCtor = TypeRegistry.for(errorSchema[1]).getErrorCtor(errorSchema) ?? Error;
        const exception = new ErrorCtor(message);
        await this.deserializeHttpMessage(errorSchema, context, response, dataObject);
        const output = {};
        for (const [name, member2] of ns.structIterator()) {
          const target = member2.getMergedTraits().jsonName ?? name;
          output[name] = this.codec.createDeserializer().readObject(member2, dataObject[target]);
        }
        throw this.mixin.decorateServiceException(Object.assign(exception, errorMetadata, {
          $fault: ns.getMergedTraits().error,
          message
        }, output), dataObject);
      }
      getDefaultContentType() {
        return "application/json";
      }
    };
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/awsExpectUnion.js
var init_awsExpectUnion = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/awsExpectUnion.js"() {
  }
});

// node_modules/@aws-sdk/xml-builder/dist-es/XmlText.js
var init_XmlText = __esm({
  "node_modules/@aws-sdk/xml-builder/dist-es/XmlText.js"() {
  }
});

// node_modules/@aws-sdk/xml-builder/dist-es/XmlNode.js
var init_XmlNode = __esm({
  "node_modules/@aws-sdk/xml-builder/dist-es/XmlNode.js"() {
  }
});

// node_modules/fast-xml-parser/src/util.js
function getAllMatches(string, regex) {
  const matches = [];
  let match = regex.exec(string);
  while (match) {
    const allmatches = [];
    allmatches.startIndex = regex.lastIndex - match[0].length;
    const len = match.length;
    for (let index = 0; index < len; index++) {
      allmatches.push(match[index]);
    }
    matches.push(allmatches);
    match = regex.exec(string);
  }
  return matches;
}
function isExist(v7) {
  return typeof v7 !== "undefined";
}
var nameStartChar, nameChar, nameRegexp, regexName, isName;
var init_util2 = __esm({
  "node_modules/fast-xml-parser/src/util.js"() {
    "use strict";
    nameStartChar = ":A-Za-z_\\u00C0-\\u00D6\\u00D8-\\u00F6\\u00F8-\\u02FF\\u0370-\\u037D\\u037F-\\u1FFF\\u200C-\\u200D\\u2070-\\u218F\\u2C00-\\u2FEF\\u3001-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFFD";
    nameChar = nameStartChar + "\\-.\\d\\u00B7\\u0300-\\u036F\\u203F-\\u2040";
    nameRegexp = "[" + nameStartChar + "][" + nameChar + "]*";
    regexName = new RegExp("^" + nameRegexp + "$");
    isName = function(string) {
      const match = regexName.exec(string);
      return !(match === null || typeof match === "undefined");
    };
  }
});

// node_modules/fast-xml-parser/src/validator.js
function validate(xmlData, options) {
  options = Object.assign({}, defaultOptions, options);
  const tags = [];
  let tagFound = false;
  let reachedRoot = false;
  if (xmlData[0] === "\uFEFF") {
    xmlData = xmlData.substr(1);
  }
  for (let i6 = 0; i6 < xmlData.length; i6++) {
    if (xmlData[i6] === "<" && xmlData[i6 + 1] === "?") {
      i6 += 2;
      i6 = readPI(xmlData, i6);
      if (i6.err) return i6;
    } else if (xmlData[i6] === "<") {
      let tagStartPos = i6;
      i6++;
      if (xmlData[i6] === "!") {
        i6 = readCommentAndCDATA(xmlData, i6);
        continue;
      } else {
        let closingTag = false;
        if (xmlData[i6] === "/") {
          closingTag = true;
          i6++;
        }
        let tagName = "";
        for (; i6 < xmlData.length && xmlData[i6] !== ">" && xmlData[i6] !== " " && xmlData[i6] !== "	" && xmlData[i6] !== "\n" && xmlData[i6] !== "\r"; i6++) {
          tagName += xmlData[i6];
        }
        tagName = tagName.trim();
        if (tagName[tagName.length - 1] === "/") {
          tagName = tagName.substring(0, tagName.length - 1);
          i6--;
        }
        if (!validateTagName(tagName)) {
          let msg;
          if (tagName.trim().length === 0) {
            msg = "Invalid space after '<'.";
          } else {
            msg = "Tag '" + tagName + "' is an invalid name.";
          }
          return getErrorObject("InvalidTag", msg, getLineNumberForPosition(xmlData, i6));
        }
        const result = readAttributeStr(xmlData, i6);
        if (result === false) {
          return getErrorObject("InvalidAttr", "Attributes for '" + tagName + "' have open quote.", getLineNumberForPosition(xmlData, i6));
        }
        let attrStr = result.value;
        i6 = result.index;
        if (attrStr[attrStr.length - 1] === "/") {
          const attrStrStart = i6 - attrStr.length;
          attrStr = attrStr.substring(0, attrStr.length - 1);
          const isValid = validateAttributeString(attrStr, options);
          if (isValid === true) {
            tagFound = true;
          } else {
            return getErrorObject(isValid.err.code, isValid.err.msg, getLineNumberForPosition(xmlData, attrStrStart + isValid.err.line));
          }
        } else if (closingTag) {
          if (!result.tagClosed) {
            return getErrorObject("InvalidTag", "Closing tag '" + tagName + "' doesn't have proper closing.", getLineNumberForPosition(xmlData, i6));
          } else if (attrStr.trim().length > 0) {
            return getErrorObject("InvalidTag", "Closing tag '" + tagName + "' can't have attributes or invalid starting.", getLineNumberForPosition(xmlData, tagStartPos));
          } else if (tags.length === 0) {
            return getErrorObject("InvalidTag", "Closing tag '" + tagName + "' has not been opened.", getLineNumberForPosition(xmlData, tagStartPos));
          } else {
            const otg = tags.pop();
            if (tagName !== otg.tagName) {
              let openPos = getLineNumberForPosition(xmlData, otg.tagStartPos);
              return getErrorObject(
                "InvalidTag",
                "Expected closing tag '" + otg.tagName + "' (opened in line " + openPos.line + ", col " + openPos.col + ") instead of closing tag '" + tagName + "'.",
                getLineNumberForPosition(xmlData, tagStartPos)
              );
            }
            if (tags.length == 0) {
              reachedRoot = true;
            }
          }
        } else {
          const isValid = validateAttributeString(attrStr, options);
          if (isValid !== true) {
            return getErrorObject(isValid.err.code, isValid.err.msg, getLineNumberForPosition(xmlData, i6 - attrStr.length + isValid.err.line));
          }
          if (reachedRoot === true) {
            return getErrorObject("InvalidXml", "Multiple possible root nodes found.", getLineNumberForPosition(xmlData, i6));
          } else if (options.unpairedTags.indexOf(tagName) !== -1) {
          } else {
            tags.push({ tagName, tagStartPos });
          }
          tagFound = true;
        }
        for (i6++; i6 < xmlData.length; i6++) {
          if (xmlData[i6] === "<") {
            if (xmlData[i6 + 1] === "!") {
              i6++;
              i6 = readCommentAndCDATA(xmlData, i6);
              continue;
            } else if (xmlData[i6 + 1] === "?") {
              i6 = readPI(xmlData, ++i6);
              if (i6.err) return i6;
            } else {
              break;
            }
          } else if (xmlData[i6] === "&") {
            const afterAmp = validateAmpersand(xmlData, i6);
            if (afterAmp == -1)
              return getErrorObject("InvalidChar", "char '&' is not expected.", getLineNumberForPosition(xmlData, i6));
            i6 = afterAmp;
          } else {
            if (reachedRoot === true && !isWhiteSpace(xmlData[i6])) {
              return getErrorObject("InvalidXml", "Extra text at the end", getLineNumberForPosition(xmlData, i6));
            }
          }
        }
        if (xmlData[i6] === "<") {
          i6--;
        }
      }
    } else {
      if (isWhiteSpace(xmlData[i6])) {
        continue;
      }
      return getErrorObject("InvalidChar", "char '" + xmlData[i6] + "' is not expected.", getLineNumberForPosition(xmlData, i6));
    }
  }
  if (!tagFound) {
    return getErrorObject("InvalidXml", "Start tag expected.", 1);
  } else if (tags.length == 1) {
    return getErrorObject("InvalidTag", "Unclosed tag '" + tags[0].tagName + "'.", getLineNumberForPosition(xmlData, tags[0].tagStartPos));
  } else if (tags.length > 0) {
    return getErrorObject("InvalidXml", "Invalid '" + JSON.stringify(tags.map((t6) => t6.tagName), null, 4).replace(/\r?\n/g, "") + "' found.", { line: 1, col: 1 });
  }
  return true;
}
function isWhiteSpace(char) {
  return char === " " || char === "	" || char === "\n" || char === "\r";
}
function readPI(xmlData, i6) {
  const start = i6;
  for (; i6 < xmlData.length; i6++) {
    if (xmlData[i6] == "?" || xmlData[i6] == " ") {
      const tagname = xmlData.substr(start, i6 - start);
      if (i6 > 5 && tagname === "xml") {
        return getErrorObject("InvalidXml", "XML declaration allowed only at the start of the document.", getLineNumberForPosition(xmlData, i6));
      } else if (xmlData[i6] == "?" && xmlData[i6 + 1] == ">") {
        i6++;
        break;
      } else {
        continue;
      }
    }
  }
  return i6;
}
function readCommentAndCDATA(xmlData, i6) {
  if (xmlData.length > i6 + 5 && xmlData[i6 + 1] === "-" && xmlData[i6 + 2] === "-") {
    for (i6 += 3; i6 < xmlData.length; i6++) {
      if (xmlData[i6] === "-" && xmlData[i6 + 1] === "-" && xmlData[i6 + 2] === ">") {
        i6 += 2;
        break;
      }
    }
  } else if (xmlData.length > i6 + 8 && xmlData[i6 + 1] === "D" && xmlData[i6 + 2] === "O" && xmlData[i6 + 3] === "C" && xmlData[i6 + 4] === "T" && xmlData[i6 + 5] === "Y" && xmlData[i6 + 6] === "P" && xmlData[i6 + 7] === "E") {
    let angleBracketsCount = 1;
    for (i6 += 8; i6 < xmlData.length; i6++) {
      if (xmlData[i6] === "<") {
        angleBracketsCount++;
      } else if (xmlData[i6] === ">") {
        angleBracketsCount--;
        if (angleBracketsCount === 0) {
          break;
        }
      }
    }
  } else if (xmlData.length > i6 + 9 && xmlData[i6 + 1] === "[" && xmlData[i6 + 2] === "C" && xmlData[i6 + 3] === "D" && xmlData[i6 + 4] === "A" && xmlData[i6 + 5] === "T" && xmlData[i6 + 6] === "A" && xmlData[i6 + 7] === "[") {
    for (i6 += 8; i6 < xmlData.length; i6++) {
      if (xmlData[i6] === "]" && xmlData[i6 + 1] === "]" && xmlData[i6 + 2] === ">") {
        i6 += 2;
        break;
      }
    }
  }
  return i6;
}
function readAttributeStr(xmlData, i6) {
  let attrStr = "";
  let startChar = "";
  let tagClosed = false;
  for (; i6 < xmlData.length; i6++) {
    if (xmlData[i6] === doubleQuote || xmlData[i6] === singleQuote) {
      if (startChar === "") {
        startChar = xmlData[i6];
      } else if (startChar !== xmlData[i6]) {
      } else {
        startChar = "";
      }
    } else if (xmlData[i6] === ">") {
      if (startChar === "") {
        tagClosed = true;
        break;
      }
    }
    attrStr += xmlData[i6];
  }
  if (startChar !== "") {
    return false;
  }
  return {
    value: attrStr,
    index: i6,
    tagClosed
  };
}
function validateAttributeString(attrStr, options) {
  const matches = getAllMatches(attrStr, validAttrStrRegxp);
  const attrNames = {};
  for (let i6 = 0; i6 < matches.length; i6++) {
    if (matches[i6][1].length === 0) {
      return getErrorObject("InvalidAttr", "Attribute '" + matches[i6][2] + "' has no space in starting.", getPositionFromMatch(matches[i6]));
    } else if (matches[i6][3] !== void 0 && matches[i6][4] === void 0) {
      return getErrorObject("InvalidAttr", "Attribute '" + matches[i6][2] + "' is without value.", getPositionFromMatch(matches[i6]));
    } else if (matches[i6][3] === void 0 && !options.allowBooleanAttributes) {
      return getErrorObject("InvalidAttr", "boolean attribute '" + matches[i6][2] + "' is not allowed.", getPositionFromMatch(matches[i6]));
    }
    const attrName = matches[i6][2];
    if (!validateAttrName(attrName)) {
      return getErrorObject("InvalidAttr", "Attribute '" + attrName + "' is an invalid name.", getPositionFromMatch(matches[i6]));
    }
    if (!attrNames.hasOwnProperty(attrName)) {
      attrNames[attrName] = 1;
    } else {
      return getErrorObject("InvalidAttr", "Attribute '" + attrName + "' is repeated.", getPositionFromMatch(matches[i6]));
    }
  }
  return true;
}
function validateNumberAmpersand(xmlData, i6) {
  let re = /\d/;
  if (xmlData[i6] === "x") {
    i6++;
    re = /[\da-fA-F]/;
  }
  for (; i6 < xmlData.length; i6++) {
    if (xmlData[i6] === ";")
      return i6;
    if (!xmlData[i6].match(re))
      break;
  }
  return -1;
}
function validateAmpersand(xmlData, i6) {
  i6++;
  if (xmlData[i6] === ";")
    return -1;
  if (xmlData[i6] === "#") {
    i6++;
    return validateNumberAmpersand(xmlData, i6);
  }
  let count = 0;
  for (; i6 < xmlData.length; i6++, count++) {
    if (xmlData[i6].match(/\w/) && count < 20)
      continue;
    if (xmlData[i6] === ";")
      break;
    return -1;
  }
  return i6;
}
function getErrorObject(code, message, lineNumber) {
  return {
    err: {
      code,
      msg: message,
      line: lineNumber.line || lineNumber,
      col: lineNumber.col
    }
  };
}
function validateAttrName(attrName) {
  return isName(attrName);
}
function validateTagName(tagname) {
  return isName(tagname);
}
function getLineNumberForPosition(xmlData, index) {
  const lines = xmlData.substring(0, index).split(/\r?\n/);
  return {
    line: lines.length,
    // column number is last line's length + 1, because column numbering starts at 1:
    col: lines[lines.length - 1].length + 1
  };
}
function getPositionFromMatch(match) {
  return match.startIndex + match[1].length;
}
var defaultOptions, doubleQuote, singleQuote, validAttrStrRegxp;
var init_validator = __esm({
  "node_modules/fast-xml-parser/src/validator.js"() {
    "use strict";
    init_util2();
    defaultOptions = {
      allowBooleanAttributes: false,
      //A tag can have attributes without any value
      unpairedTags: []
    };
    doubleQuote = '"';
    singleQuote = "'";
    validAttrStrRegxp = new RegExp(`(\\s*)([^\\s=]+)(\\s*=)?(\\s*(['"])(([\\s\\S])*?)\\5)?`, "g");
  }
});

// node_modules/fast-xml-parser/src/xmlparser/OptionsBuilder.js
var defaultOptions2, buildOptions;
var init_OptionsBuilder = __esm({
  "node_modules/fast-xml-parser/src/xmlparser/OptionsBuilder.js"() {
    defaultOptions2 = {
      preserveOrder: false,
      attributeNamePrefix: "@_",
      attributesGroupName: false,
      textNodeName: "#text",
      ignoreAttributes: true,
      removeNSPrefix: false,
      // remove NS from tag name or attribute name if true
      allowBooleanAttributes: false,
      //a tag can have attributes without any value
      //ignoreRootElement : false,
      parseTagValue: true,
      parseAttributeValue: false,
      trimValues: true,
      //Trim string values of tag and attributes
      cdataPropName: false,
      numberParseOptions: {
        hex: true,
        leadingZeros: true,
        eNotation: true
      },
      tagValueProcessor: function(tagName, val) {
        return val;
      },
      attributeValueProcessor: function(attrName, val) {
        return val;
      },
      stopNodes: [],
      //nested tags will not be parsed even for errors
      alwaysCreateTextNode: false,
      isArray: () => false,
      commentPropName: false,
      unpairedTags: [],
      processEntities: true,
      htmlEntities: false,
      ignoreDeclaration: false,
      ignorePiTags: false,
      transformTagName: false,
      transformAttributeName: false,
      updateTag: function(tagName, jPath, attrs) {
        return tagName;
      },
      // skipEmptyListItem: false
      captureMetaData: false
    };
    buildOptions = function(options) {
      return Object.assign({}, defaultOptions2, options);
    };
  }
});

// node_modules/fast-xml-parser/src/xmlparser/xmlNode.js
var METADATA_SYMBOL, XmlNode;
var init_xmlNode = __esm({
  "node_modules/fast-xml-parser/src/xmlparser/xmlNode.js"() {
    "use strict";
    if (typeof Symbol !== "function") {
      METADATA_SYMBOL = "@@xmlMetadata";
    } else {
      METADATA_SYMBOL = /* @__PURE__ */ Symbol("XML Node Metadata");
    }
    XmlNode = class {
      constructor(tagname) {
        this.tagname = tagname;
        this.child = [];
        this[":@"] = {};
      }
      add(key, val) {
        if (key === "__proto__") key = "#__proto__";
        this.child.push({ [key]: val });
      }
      addChild(node, startIndex) {
        if (node.tagname === "__proto__") node.tagname = "#__proto__";
        if (node[":@"] && Object.keys(node[":@"]).length > 0) {
          this.child.push({ [node.tagname]: node.child, [":@"]: node[":@"] });
        } else {
          this.child.push({ [node.tagname]: node.child });
        }
        if (startIndex !== void 0) {
          this.child[this.child.length - 1][METADATA_SYMBOL] = { startIndex };
        }
      }
      /** symbol used for metadata */
      static getMetaDataSymbol() {
        return METADATA_SYMBOL;
      }
    };
  }
});

// node_modules/fast-xml-parser/src/xmlparser/DocTypeReader.js
function readDocType(xmlData, i6) {
  const entities = {};
  if (xmlData[i6 + 3] === "O" && xmlData[i6 + 4] === "C" && xmlData[i6 + 5] === "T" && xmlData[i6 + 6] === "Y" && xmlData[i6 + 7] === "P" && xmlData[i6 + 8] === "E") {
    i6 = i6 + 9;
    let angleBracketsCount = 1;
    let hasBody = false, comment = false;
    let exp = "";
    for (; i6 < xmlData.length; i6++) {
      if (xmlData[i6] === "<" && !comment) {
        if (hasBody && hasSeq(xmlData, "!ENTITY", i6)) {
          i6 += 7;
          let entityName, val;
          [entityName, val, i6] = readEntityExp(xmlData, i6 + 1);
          if (val.indexOf("&") === -1)
            entities[entityName] = {
              regx: RegExp(`&${entityName};`, "g"),
              val
            };
        } else if (hasBody && hasSeq(xmlData, "!ELEMENT", i6)) {
          i6 += 8;
          const { index } = readElementExp(xmlData, i6 + 1);
          i6 = index;
        } else if (hasBody && hasSeq(xmlData, "!ATTLIST", i6)) {
          i6 += 8;
        } else if (hasBody && hasSeq(xmlData, "!NOTATION", i6)) {
          i6 += 9;
          const { index } = readNotationExp(xmlData, i6 + 1);
          i6 = index;
        } else if (hasSeq(xmlData, "!--", i6)) comment = true;
        else throw new Error(`Invalid DOCTYPE`);
        angleBracketsCount++;
        exp = "";
      } else if (xmlData[i6] === ">") {
        if (comment) {
          if (xmlData[i6 - 1] === "-" && xmlData[i6 - 2] === "-") {
            comment = false;
            angleBracketsCount--;
          }
        } else {
          angleBracketsCount--;
        }
        if (angleBracketsCount === 0) {
          break;
        }
      } else if (xmlData[i6] === "[") {
        hasBody = true;
      } else {
        exp += xmlData[i6];
      }
    }
    if (angleBracketsCount !== 0) {
      throw new Error(`Unclosed DOCTYPE`);
    }
  } else {
    throw new Error(`Invalid Tag instead of DOCTYPE`);
  }
  return { entities, i: i6 };
}
function readEntityExp(xmlData, i6) {
  i6 = skipWhitespace(xmlData, i6);
  let entityName = "";
  while (i6 < xmlData.length && !/\s/.test(xmlData[i6]) && xmlData[i6] !== '"' && xmlData[i6] !== "'") {
    entityName += xmlData[i6];
    i6++;
  }
  validateEntityName(entityName);
  i6 = skipWhitespace(xmlData, i6);
  if (xmlData.substring(i6, i6 + 6).toUpperCase() === "SYSTEM") {
    throw new Error("External entities are not supported");
  } else if (xmlData[i6] === "%") {
    throw new Error("Parameter entities are not supported");
  }
  let entityValue = "";
  [i6, entityValue] = readIdentifierVal(xmlData, i6, "entity");
  i6--;
  return [entityName, entityValue, i6];
}
function readNotationExp(xmlData, i6) {
  i6 = skipWhitespace(xmlData, i6);
  let notationName = "";
  while (i6 < xmlData.length && !/\s/.test(xmlData[i6])) {
    notationName += xmlData[i6];
    i6++;
  }
  validateEntityName(notationName);
  i6 = skipWhitespace(xmlData, i6);
  const identifierType = xmlData.substring(i6, i6 + 6).toUpperCase();
  if (identifierType !== "SYSTEM" && identifierType !== "PUBLIC") {
    throw new Error(`Expected SYSTEM or PUBLIC, found "${identifierType}"`);
  }
  i6 += identifierType.length;
  i6 = skipWhitespace(xmlData, i6);
  let publicIdentifier = null;
  let systemIdentifier = null;
  if (identifierType === "PUBLIC") {
    [i6, publicIdentifier] = readIdentifierVal(xmlData, i6, "publicIdentifier");
    i6 = skipWhitespace(xmlData, i6);
    if (xmlData[i6] === '"' || xmlData[i6] === "'") {
      [i6, systemIdentifier] = readIdentifierVal(xmlData, i6, "systemIdentifier");
    }
  } else if (identifierType === "SYSTEM") {
    [i6, systemIdentifier] = readIdentifierVal(xmlData, i6, "systemIdentifier");
    if (!systemIdentifier) {
      throw new Error("Missing mandatory system identifier for SYSTEM notation");
    }
  }
  return { notationName, publicIdentifier, systemIdentifier, index: --i6 };
}
function readIdentifierVal(xmlData, i6, type) {
  let identifierVal = "";
  const startChar = xmlData[i6];
  if (startChar !== '"' && startChar !== "'") {
    throw new Error(`Expected quoted string, found "${startChar}"`);
  }
  i6++;
  while (i6 < xmlData.length && xmlData[i6] !== startChar) {
    identifierVal += xmlData[i6];
    i6++;
  }
  if (xmlData[i6] !== startChar) {
    throw new Error(`Unterminated ${type} value`);
  }
  i6++;
  return [i6, identifierVal];
}
function readElementExp(xmlData, i6) {
  i6 = skipWhitespace(xmlData, i6);
  let elementName = "";
  while (i6 < xmlData.length && !/\s/.test(xmlData[i6])) {
    elementName += xmlData[i6];
    i6++;
  }
  if (!validateEntityName(elementName)) {
    throw new Error(`Invalid element name: "${elementName}"`);
  }
  i6 = skipWhitespace(xmlData, i6);
  let contentModel = "";
  if (xmlData[i6] === "E" && hasSeq(xmlData, "MPTY", i6)) i6 += 4;
  else if (xmlData[i6] === "A" && hasSeq(xmlData, "NY", i6)) i6 += 2;
  else if (xmlData[i6] === "(") {
    i6++;
    while (i6 < xmlData.length && xmlData[i6] !== ")") {
      contentModel += xmlData[i6];
      i6++;
    }
    if (xmlData[i6] !== ")") {
      throw new Error("Unterminated content model");
    }
  } else {
    throw new Error(`Invalid Element Expression, found "${xmlData[i6]}"`);
  }
  return {
    elementName,
    contentModel: contentModel.trim(),
    index: i6
  };
}
function hasSeq(data, seq, i6) {
  for (let j6 = 0; j6 < seq.length; j6++) {
    if (seq[j6] !== data[i6 + j6 + 1]) return false;
  }
  return true;
}
function validateEntityName(name) {
  if (isName(name))
    return name;
  else
    throw new Error(`Invalid entity name ${name}`);
}
var skipWhitespace;
var init_DocTypeReader = __esm({
  "node_modules/fast-xml-parser/src/xmlparser/DocTypeReader.js"() {
    init_util2();
    skipWhitespace = (data, index) => {
      while (index < data.length && /\s/.test(data[index])) {
        index++;
      }
      return index;
    };
  }
});

// node_modules/strnum/strnum.js
function toNumber(str, options = {}) {
  options = Object.assign({}, consider, options);
  if (!str || typeof str !== "string") return str;
  let trimmedStr = str.trim();
  if (options.skipLike !== void 0 && options.skipLike.test(trimmedStr)) return str;
  else if (str === "0") return 0;
  else if (options.hex && hexRegex.test(trimmedStr)) {
    return parse_int(trimmedStr, 16);
  } else if (trimmedStr.includes("e") || trimmedStr.includes("E")) {
    return resolveEnotation(str, trimmedStr, options);
  } else {
    const match = numRegex.exec(trimmedStr);
    if (match) {
      const sign2 = match[1] || "";
      const leadingZeros = match[2];
      let numTrimmedByZeros = trimZeros(match[3]);
      const decimalAdjacentToLeadingZeros = sign2 ? (
        // 0., -00., 000.
        str[leadingZeros.length + 1] === "."
      ) : str[leadingZeros.length] === ".";
      if (!options.leadingZeros && (leadingZeros.length > 1 || leadingZeros.length === 1 && !decimalAdjacentToLeadingZeros)) {
        return str;
      } else {
        const num = Number(trimmedStr);
        const parsedStr = String(num);
        if (num === 0) return num;
        if (parsedStr.search(/[eE]/) !== -1) {
          if (options.eNotation) return num;
          else return str;
        } else if (trimmedStr.indexOf(".") !== -1) {
          if (parsedStr === "0") return num;
          else if (parsedStr === numTrimmedByZeros) return num;
          else if (parsedStr === `${sign2}${numTrimmedByZeros}`) return num;
          else return str;
        }
        let n6 = leadingZeros ? numTrimmedByZeros : trimmedStr;
        if (leadingZeros) {
          return n6 === parsedStr || sign2 + n6 === parsedStr ? num : str;
        } else {
          return n6 === parsedStr || n6 === sign2 + parsedStr ? num : str;
        }
      }
    } else {
      return str;
    }
  }
}
function resolveEnotation(str, trimmedStr, options) {
  if (!options.eNotation) return str;
  const notation = trimmedStr.match(eNotationRegx);
  if (notation) {
    let sign2 = notation[1] || "";
    const eChar = notation[3].indexOf("e") === -1 ? "E" : "e";
    const leadingZeros = notation[2];
    const eAdjacentToLeadingZeros = sign2 ? (
      // 0E.
      str[leadingZeros.length + 1] === eChar
    ) : str[leadingZeros.length] === eChar;
    if (leadingZeros.length > 1 && eAdjacentToLeadingZeros) return str;
    else if (leadingZeros.length === 1 && (notation[3].startsWith(`.${eChar}`) || notation[3][0] === eChar)) {
      return Number(trimmedStr);
    } else if (options.leadingZeros && !eAdjacentToLeadingZeros) {
      trimmedStr = (notation[1] || "") + notation[3];
      return Number(trimmedStr);
    } else return str;
  } else {
    return str;
  }
}
function trimZeros(numStr) {
  if (numStr && numStr.indexOf(".") !== -1) {
    numStr = numStr.replace(/0+$/, "");
    if (numStr === ".") numStr = "0";
    else if (numStr[0] === ".") numStr = "0" + numStr;
    else if (numStr[numStr.length - 1] === ".") numStr = numStr.substring(0, numStr.length - 1);
    return numStr;
  }
  return numStr;
}
function parse_int(numStr, base) {
  if (parseInt) return parseInt(numStr, base);
  else if (Number.parseInt) return Number.parseInt(numStr, base);
  else if (window && window.parseInt) return window.parseInt(numStr, base);
  else throw new Error("parseInt, Number.parseInt, window.parseInt are not supported");
}
var hexRegex, numRegex, consider, eNotationRegx;
var init_strnum = __esm({
  "node_modules/strnum/strnum.js"() {
    hexRegex = /^[-+]?0x[a-fA-F0-9]+$/;
    numRegex = /^([\-\+])?(0*)([0-9]*(\.[0-9]*)?)$/;
    consider = {
      hex: true,
      // oct: false,
      leadingZeros: true,
      decimalPoint: ".",
      eNotation: true
      //skipLike: /regex/
    };
    eNotationRegx = /^([-+])?(0*)(\d*(\.\d*)?[eE][-\+]?\d+)$/;
  }
});

// node_modules/fast-xml-parser/src/ignoreAttributes.js
function getIgnoreAttributesFn(ignoreAttributes) {
  if (typeof ignoreAttributes === "function") {
    return ignoreAttributes;
  }
  if (Array.isArray(ignoreAttributes)) {
    return (attrName) => {
      for (const pattern of ignoreAttributes) {
        if (typeof pattern === "string" && attrName === pattern) {
          return true;
        }
        if (pattern instanceof RegExp && pattern.test(attrName)) {
          return true;
        }
      }
    };
  }
  return () => false;
}
var init_ignoreAttributes = __esm({
  "node_modules/fast-xml-parser/src/ignoreAttributes.js"() {
  }
});

// node_modules/fast-xml-parser/src/xmlparser/OrderedObjParser.js
function addExternalEntities(externalEntities) {
  const entKeys = Object.keys(externalEntities);
  for (let i6 = 0; i6 < entKeys.length; i6++) {
    const ent = entKeys[i6];
    this.lastEntities[ent] = {
      regex: new RegExp("&" + ent + ";", "g"),
      val: externalEntities[ent]
    };
  }
}
function parseTextData(val, tagName, jPath, dontTrim, hasAttributes, isLeafNode, escapeEntities) {
  if (val !== void 0) {
    if (this.options.trimValues && !dontTrim) {
      val = val.trim();
    }
    if (val.length > 0) {
      if (!escapeEntities) val = this.replaceEntitiesValue(val);
      const newval = this.options.tagValueProcessor(tagName, val, jPath, hasAttributes, isLeafNode);
      if (newval === null || newval === void 0) {
        return val;
      } else if (typeof newval !== typeof val || newval !== val) {
        return newval;
      } else if (this.options.trimValues) {
        return parseValue(val, this.options.parseTagValue, this.options.numberParseOptions);
      } else {
        const trimmedVal = val.trim();
        if (trimmedVal === val) {
          return parseValue(val, this.options.parseTagValue, this.options.numberParseOptions);
        } else {
          return val;
        }
      }
    }
  }
}
function resolveNameSpace(tagname) {
  if (this.options.removeNSPrefix) {
    const tags = tagname.split(":");
    const prefix = tagname.charAt(0) === "/" ? "/" : "";
    if (tags[0] === "xmlns") {
      return "";
    }
    if (tags.length === 2) {
      tagname = prefix + tags[1];
    }
  }
  return tagname;
}
function buildAttributesMap(attrStr, jPath, tagName) {
  if (this.options.ignoreAttributes !== true && typeof attrStr === "string") {
    const matches = getAllMatches(attrStr, attrsRegx);
    const len = matches.length;
    const attrs = {};
    for (let i6 = 0; i6 < len; i6++) {
      const attrName = this.resolveNameSpace(matches[i6][1]);
      if (this.ignoreAttributesFn(attrName, jPath)) {
        continue;
      }
      let oldVal = matches[i6][4];
      let aName = this.options.attributeNamePrefix + attrName;
      if (attrName.length) {
        if (this.options.transformAttributeName) {
          aName = this.options.transformAttributeName(aName);
        }
        if (aName === "__proto__") aName = "#__proto__";
        if (oldVal !== void 0) {
          if (this.options.trimValues) {
            oldVal = oldVal.trim();
          }
          oldVal = this.replaceEntitiesValue(oldVal);
          const newVal = this.options.attributeValueProcessor(attrName, oldVal, jPath);
          if (newVal === null || newVal === void 0) {
            attrs[aName] = oldVal;
          } else if (typeof newVal !== typeof oldVal || newVal !== oldVal) {
            attrs[aName] = newVal;
          } else {
            attrs[aName] = parseValue(
              oldVal,
              this.options.parseAttributeValue,
              this.options.numberParseOptions
            );
          }
        } else if (this.options.allowBooleanAttributes) {
          attrs[aName] = true;
        }
      }
    }
    if (!Object.keys(attrs).length) {
      return;
    }
    if (this.options.attributesGroupName) {
      const attrCollection = {};
      attrCollection[this.options.attributesGroupName] = attrs;
      return attrCollection;
    }
    return attrs;
  }
}
function addChild(currentNode, childNode, jPath, startIndex) {
  if (!this.options.captureMetaData) startIndex = void 0;
  const result = this.options.updateTag(childNode.tagname, jPath, childNode[":@"]);
  if (result === false) {
  } else if (typeof result === "string") {
    childNode.tagname = result;
    currentNode.addChild(childNode, startIndex);
  } else {
    currentNode.addChild(childNode, startIndex);
  }
}
function saveTextToParentTag(textData, currentNode, jPath, isLeafNode) {
  if (textData) {
    if (isLeafNode === void 0) isLeafNode = currentNode.child.length === 0;
    textData = this.parseTextData(
      textData,
      currentNode.tagname,
      jPath,
      false,
      currentNode[":@"] ? Object.keys(currentNode[":@"]).length !== 0 : false,
      isLeafNode
    );
    if (textData !== void 0 && textData !== "")
      currentNode.add(this.options.textNodeName, textData);
    textData = "";
  }
  return textData;
}
function isItStopNode(stopNodes, jPath, currentTagName) {
  const allNodesExp = "*." + currentTagName;
  for (const stopNodePath in stopNodes) {
    const stopNodeExp = stopNodes[stopNodePath];
    if (allNodesExp === stopNodeExp || jPath === stopNodeExp) return true;
  }
  return false;
}
function tagExpWithClosingIndex(xmlData, i6, closingChar = ">") {
  let attrBoundary;
  let tagExp = "";
  for (let index = i6; index < xmlData.length; index++) {
    let ch = xmlData[index];
    if (attrBoundary) {
      if (ch === attrBoundary) attrBoundary = "";
    } else if (ch === '"' || ch === "'") {
      attrBoundary = ch;
    } else if (ch === closingChar[0]) {
      if (closingChar[1]) {
        if (xmlData[index + 1] === closingChar[1]) {
          return {
            data: tagExp,
            index
          };
        }
      } else {
        return {
          data: tagExp,
          index
        };
      }
    } else if (ch === "	") {
      ch = " ";
    }
    tagExp += ch;
  }
}
function findClosingIndex(xmlData, str, i6, errMsg) {
  const closingIndex = xmlData.indexOf(str, i6);
  if (closingIndex === -1) {
    throw new Error(errMsg);
  } else {
    return closingIndex + str.length - 1;
  }
}
function readTagExp(xmlData, i6, removeNSPrefix, closingChar = ">") {
  const result = tagExpWithClosingIndex(xmlData, i6 + 1, closingChar);
  if (!result) return;
  let tagExp = result.data;
  const closeIndex = result.index;
  const separatorIndex = tagExp.search(/\s/);
  let tagName = tagExp;
  let attrExpPresent = true;
  if (separatorIndex !== -1) {
    tagName = tagExp.substring(0, separatorIndex);
    tagExp = tagExp.substring(separatorIndex + 1).trimStart();
  }
  const rawTagName = tagName;
  if (removeNSPrefix) {
    const colonIndex = tagName.indexOf(":");
    if (colonIndex !== -1) {
      tagName = tagName.substr(colonIndex + 1);
      attrExpPresent = tagName !== result.data.substr(colonIndex + 1);
    }
  }
  return {
    tagName,
    tagExp,
    closeIndex,
    attrExpPresent,
    rawTagName
  };
}
function readStopNodeData(xmlData, tagName, i6) {
  const startIndex = i6;
  let openTagCount = 1;
  for (; i6 < xmlData.length; i6++) {
    if (xmlData[i6] === "<") {
      if (xmlData[i6 + 1] === "/") {
        const closeIndex = findClosingIndex(xmlData, ">", i6, `${tagName} is not closed`);
        let closeTagName = xmlData.substring(i6 + 2, closeIndex).trim();
        if (closeTagName === tagName) {
          openTagCount--;
          if (openTagCount === 0) {
            return {
              tagContent: xmlData.substring(startIndex, i6),
              i: closeIndex
            };
          }
        }
        i6 = closeIndex;
      } else if (xmlData[i6 + 1] === "?") {
        const closeIndex = findClosingIndex(xmlData, "?>", i6 + 1, "StopNode is not closed.");
        i6 = closeIndex;
      } else if (xmlData.substr(i6 + 1, 3) === "!--") {
        const closeIndex = findClosingIndex(xmlData, "-->", i6 + 3, "StopNode is not closed.");
        i6 = closeIndex;
      } else if (xmlData.substr(i6 + 1, 2) === "![") {
        const closeIndex = findClosingIndex(xmlData, "]]>", i6, "StopNode is not closed.") - 2;
        i6 = closeIndex;
      } else {
        const tagData = readTagExp(xmlData, i6, ">");
        if (tagData) {
          const openTagName = tagData && tagData.tagName;
          if (openTagName === tagName && tagData.tagExp[tagData.tagExp.length - 1] !== "/") {
            openTagCount++;
          }
          i6 = tagData.closeIndex;
        }
      }
    }
  }
}
function parseValue(val, shouldParse, options) {
  if (shouldParse && typeof val === "string") {
    const newval = val.trim();
    if (newval === "true") return true;
    else if (newval === "false") return false;
    else return toNumber(val, options);
  } else {
    if (isExist(val)) {
      return val;
    } else {
      return "";
    }
  }
}
var OrderedObjParser, attrsRegx, parseXml, replaceEntitiesValue;
var init_OrderedObjParser = __esm({
  "node_modules/fast-xml-parser/src/xmlparser/OrderedObjParser.js"() {
    "use strict";
    init_util2();
    init_xmlNode();
    init_DocTypeReader();
    init_strnum();
    init_ignoreAttributes();
    OrderedObjParser = class {
      constructor(options) {
        this.options = options;
        this.currentNode = null;
        this.tagsNodeStack = [];
        this.docTypeEntities = {};
        this.lastEntities = {
          "apos": { regex: /&(apos|#39|#x27);/g, val: "'" },
          "gt": { regex: /&(gt|#62|#x3E);/g, val: ">" },
          "lt": { regex: /&(lt|#60|#x3C);/g, val: "<" },
          "quot": { regex: /&(quot|#34|#x22);/g, val: '"' }
        };
        this.ampEntity = { regex: /&(amp|#38|#x26);/g, val: "&" };
        this.htmlEntities = {
          "space": { regex: /&(nbsp|#160);/g, val: " " },
          // "lt" : { regex: /&(lt|#60);/g, val: "<" },
          // "gt" : { regex: /&(gt|#62);/g, val: ">" },
          // "amp" : { regex: /&(amp|#38);/g, val: "&" },
          // "quot" : { regex: /&(quot|#34);/g, val: "\"" },
          // "apos" : { regex: /&(apos|#39);/g, val: "'" },
          "cent": { regex: /&(cent|#162);/g, val: "\xA2" },
          "pound": { regex: /&(pound|#163);/g, val: "\xA3" },
          "yen": { regex: /&(yen|#165);/g, val: "\xA5" },
          "euro": { regex: /&(euro|#8364);/g, val: "\u20AC" },
          "copyright": { regex: /&(copy|#169);/g, val: "\xA9" },
          "reg": { regex: /&(reg|#174);/g, val: "\xAE" },
          "inr": { regex: /&(inr|#8377);/g, val: "\u20B9" },
          "num_dec": { regex: /&#([0-9]{1,7});/g, val: (_, str) => String.fromCodePoint(Number.parseInt(str, 10)) },
          "num_hex": { regex: /&#x([0-9a-fA-F]{1,6});/g, val: (_, str) => String.fromCodePoint(Number.parseInt(str, 16)) }
        };
        this.addExternalEntities = addExternalEntities;
        this.parseXml = parseXml;
        this.parseTextData = parseTextData;
        this.resolveNameSpace = resolveNameSpace;
        this.buildAttributesMap = buildAttributesMap;
        this.isItStopNode = isItStopNode;
        this.replaceEntitiesValue = replaceEntitiesValue;
        this.readStopNodeData = readStopNodeData;
        this.saveTextToParentTag = saveTextToParentTag;
        this.addChild = addChild;
        this.ignoreAttributesFn = getIgnoreAttributesFn(this.options.ignoreAttributes);
      }
    };
    attrsRegx = new RegExp(`([^\\s=]+)\\s*(=\\s*(['"])([\\s\\S]*?)\\3)?`, "gm");
    parseXml = function(xmlData) {
      xmlData = xmlData.replace(/\r\n?/g, "\n");
      const xmlObj = new XmlNode("!xml");
      let currentNode = xmlObj;
      let textData = "";
      let jPath = "";
      for (let i6 = 0; i6 < xmlData.length; i6++) {
        const ch = xmlData[i6];
        if (ch === "<") {
          if (xmlData[i6 + 1] === "/") {
            const closeIndex = findClosingIndex(xmlData, ">", i6, "Closing Tag is not closed.");
            let tagName = xmlData.substring(i6 + 2, closeIndex).trim();
            if (this.options.removeNSPrefix) {
              const colonIndex = tagName.indexOf(":");
              if (colonIndex !== -1) {
                tagName = tagName.substr(colonIndex + 1);
              }
            }
            if (this.options.transformTagName) {
              tagName = this.options.transformTagName(tagName);
            }
            if (currentNode) {
              textData = this.saveTextToParentTag(textData, currentNode, jPath);
            }
            const lastTagName = jPath.substring(jPath.lastIndexOf(".") + 1);
            if (tagName && this.options.unpairedTags.indexOf(tagName) !== -1) {
              throw new Error(`Unpaired tag can not be used as closing tag: </${tagName}>`);
            }
            let propIndex = 0;
            if (lastTagName && this.options.unpairedTags.indexOf(lastTagName) !== -1) {
              propIndex = jPath.lastIndexOf(".", jPath.lastIndexOf(".") - 1);
              this.tagsNodeStack.pop();
            } else {
              propIndex = jPath.lastIndexOf(".");
            }
            jPath = jPath.substring(0, propIndex);
            currentNode = this.tagsNodeStack.pop();
            textData = "";
            i6 = closeIndex;
          } else if (xmlData[i6 + 1] === "?") {
            let tagData = readTagExp(xmlData, i6, false, "?>");
            if (!tagData) throw new Error("Pi Tag is not closed.");
            textData = this.saveTextToParentTag(textData, currentNode, jPath);
            if (this.options.ignoreDeclaration && tagData.tagName === "?xml" || this.options.ignorePiTags) {
            } else {
              const childNode = new XmlNode(tagData.tagName);
              childNode.add(this.options.textNodeName, "");
              if (tagData.tagName !== tagData.tagExp && tagData.attrExpPresent) {
                childNode[":@"] = this.buildAttributesMap(tagData.tagExp, jPath, tagData.tagName);
              }
              this.addChild(currentNode, childNode, jPath, i6);
            }
            i6 = tagData.closeIndex + 1;
          } else if (xmlData.substr(i6 + 1, 3) === "!--") {
            const endIndex = findClosingIndex(xmlData, "-->", i6 + 4, "Comment is not closed.");
            if (this.options.commentPropName) {
              const comment = xmlData.substring(i6 + 4, endIndex - 2);
              textData = this.saveTextToParentTag(textData, currentNode, jPath);
              currentNode.add(this.options.commentPropName, [{ [this.options.textNodeName]: comment }]);
            }
            i6 = endIndex;
          } else if (xmlData.substr(i6 + 1, 2) === "!D") {
            const result = readDocType(xmlData, i6);
            this.docTypeEntities = result.entities;
            i6 = result.i;
          } else if (xmlData.substr(i6 + 1, 2) === "![") {
            const closeIndex = findClosingIndex(xmlData, "]]>", i6, "CDATA is not closed.") - 2;
            const tagExp = xmlData.substring(i6 + 9, closeIndex);
            textData = this.saveTextToParentTag(textData, currentNode, jPath);
            let val = this.parseTextData(tagExp, currentNode.tagname, jPath, true, false, true, true);
            if (val == void 0) val = "";
            if (this.options.cdataPropName) {
              currentNode.add(this.options.cdataPropName, [{ [this.options.textNodeName]: tagExp }]);
            } else {
              currentNode.add(this.options.textNodeName, val);
            }
            i6 = closeIndex + 2;
          } else {
            let result = readTagExp(xmlData, i6, this.options.removeNSPrefix);
            let tagName = result.tagName;
            const rawTagName = result.rawTagName;
            let tagExp = result.tagExp;
            let attrExpPresent = result.attrExpPresent;
            let closeIndex = result.closeIndex;
            if (this.options.transformTagName) {
              tagName = this.options.transformTagName(tagName);
            }
            if (currentNode && textData) {
              if (currentNode.tagname !== "!xml") {
                textData = this.saveTextToParentTag(textData, currentNode, jPath, false);
              }
            }
            const lastTag = currentNode;
            if (lastTag && this.options.unpairedTags.indexOf(lastTag.tagname) !== -1) {
              currentNode = this.tagsNodeStack.pop();
              jPath = jPath.substring(0, jPath.lastIndexOf("."));
            }
            if (tagName !== xmlObj.tagname) {
              jPath += jPath ? "." + tagName : tagName;
            }
            const startIndex = i6;
            if (this.isItStopNode(this.options.stopNodes, jPath, tagName)) {
              let tagContent = "";
              if (tagExp.length > 0 && tagExp.lastIndexOf("/") === tagExp.length - 1) {
                if (tagName[tagName.length - 1] === "/") {
                  tagName = tagName.substr(0, tagName.length - 1);
                  jPath = jPath.substr(0, jPath.length - 1);
                  tagExp = tagName;
                } else {
                  tagExp = tagExp.substr(0, tagExp.length - 1);
                }
                i6 = result.closeIndex;
              } else if (this.options.unpairedTags.indexOf(tagName) !== -1) {
                i6 = result.closeIndex;
              } else {
                const result2 = this.readStopNodeData(xmlData, rawTagName, closeIndex + 1);
                if (!result2) throw new Error(`Unexpected end of ${rawTagName}`);
                i6 = result2.i;
                tagContent = result2.tagContent;
              }
              const childNode = new XmlNode(tagName);
              if (tagName !== tagExp && attrExpPresent) {
                childNode[":@"] = this.buildAttributesMap(tagExp, jPath, tagName);
              }
              if (tagContent) {
                tagContent = this.parseTextData(tagContent, tagName, jPath, true, attrExpPresent, true, true);
              }
              jPath = jPath.substr(0, jPath.lastIndexOf("."));
              childNode.add(this.options.textNodeName, tagContent);
              this.addChild(currentNode, childNode, jPath, startIndex);
            } else {
              if (tagExp.length > 0 && tagExp.lastIndexOf("/") === tagExp.length - 1) {
                if (tagName[tagName.length - 1] === "/") {
                  tagName = tagName.substr(0, tagName.length - 1);
                  jPath = jPath.substr(0, jPath.length - 1);
                  tagExp = tagName;
                } else {
                  tagExp = tagExp.substr(0, tagExp.length - 1);
                }
                if (this.options.transformTagName) {
                  tagName = this.options.transformTagName(tagName);
                }
                const childNode = new XmlNode(tagName);
                if (tagName !== tagExp && attrExpPresent) {
                  childNode[":@"] = this.buildAttributesMap(tagExp, jPath, tagName);
                }
                this.addChild(currentNode, childNode, jPath, startIndex);
                jPath = jPath.substr(0, jPath.lastIndexOf("."));
              } else {
                const childNode = new XmlNode(tagName);
                this.tagsNodeStack.push(currentNode);
                if (tagName !== tagExp && attrExpPresent) {
                  childNode[":@"] = this.buildAttributesMap(tagExp, jPath, tagName);
                }
                this.addChild(currentNode, childNode, jPath, startIndex);
                currentNode = childNode;
              }
              textData = "";
              i6 = closeIndex;
            }
          }
        } else {
          textData += xmlData[i6];
        }
      }
      return xmlObj.child;
    };
    replaceEntitiesValue = function(val) {
      if (this.options.processEntities) {
        for (let entityName in this.docTypeEntities) {
          const entity = this.docTypeEntities[entityName];
          val = val.replace(entity.regx, entity.val);
        }
        for (let entityName in this.lastEntities) {
          const entity = this.lastEntities[entityName];
          val = val.replace(entity.regex, entity.val);
        }
        if (this.options.htmlEntities) {
          for (let entityName in this.htmlEntities) {
            const entity = this.htmlEntities[entityName];
            val = val.replace(entity.regex, entity.val);
          }
        }
        val = val.replace(this.ampEntity.regex, this.ampEntity.val);
      }
      return val;
    };
  }
});

// node_modules/fast-xml-parser/src/xmlparser/node2json.js
function prettify(node, options) {
  return compress(node, options);
}
function compress(arr, options, jPath) {
  let text;
  const compressedObj = {};
  for (let i6 = 0; i6 < arr.length; i6++) {
    const tagObj = arr[i6];
    const property = propName(tagObj);
    let newJpath = "";
    if (jPath === void 0) newJpath = property;
    else newJpath = jPath + "." + property;
    if (property === options.textNodeName) {
      if (text === void 0) text = tagObj[property];
      else text += "" + tagObj[property];
    } else if (property === void 0) {
      continue;
    } else if (tagObj[property]) {
      let val = compress(tagObj[property], options, newJpath);
      const isLeaf = isLeafTag(val, options);
      if (tagObj[METADATA_SYMBOL2] !== void 0) {
        val[METADATA_SYMBOL2] = tagObj[METADATA_SYMBOL2];
      }
      if (tagObj[":@"]) {
        assignAttributes(val, tagObj[":@"], newJpath, options);
      } else if (Object.keys(val).length === 1 && val[options.textNodeName] !== void 0 && !options.alwaysCreateTextNode) {
        val = val[options.textNodeName];
      } else if (Object.keys(val).length === 0) {
        if (options.alwaysCreateTextNode) val[options.textNodeName] = "";
        else val = "";
      }
      if (compressedObj[property] !== void 0 && compressedObj.hasOwnProperty(property)) {
        if (!Array.isArray(compressedObj[property])) {
          compressedObj[property] = [compressedObj[property]];
        }
        compressedObj[property].push(val);
      } else {
        if (options.isArray(property, newJpath, isLeaf)) {
          compressedObj[property] = [val];
        } else {
          compressedObj[property] = val;
        }
      }
    }
  }
  if (typeof text === "string") {
    if (text.length > 0) compressedObj[options.textNodeName] = text;
  } else if (text !== void 0) compressedObj[options.textNodeName] = text;
  return compressedObj;
}
function propName(obj) {
  const keys = Object.keys(obj);
  for (let i6 = 0; i6 < keys.length; i6++) {
    const key = keys[i6];
    if (key !== ":@") return key;
  }
}
function assignAttributes(obj, attrMap, jpath, options) {
  if (attrMap) {
    const keys = Object.keys(attrMap);
    const len = keys.length;
    for (let i6 = 0; i6 < len; i6++) {
      const atrrName = keys[i6];
      if (options.isArray(atrrName, jpath + "." + atrrName, true, true)) {
        obj[atrrName] = [attrMap[atrrName]];
      } else {
        obj[atrrName] = attrMap[atrrName];
      }
    }
  }
}
function isLeafTag(obj, options) {
  const { textNodeName } = options;
  const propCount = Object.keys(obj).length;
  if (propCount === 0) {
    return true;
  }
  if (propCount === 1 && (obj[textNodeName] || typeof obj[textNodeName] === "boolean" || obj[textNodeName] === 0)) {
    return true;
  }
  return false;
}
var METADATA_SYMBOL2;
var init_node2json = __esm({
  "node_modules/fast-xml-parser/src/xmlparser/node2json.js"() {
    "use strict";
    init_xmlNode();
    METADATA_SYMBOL2 = XmlNode.getMetaDataSymbol();
  }
});

// node_modules/fast-xml-parser/src/xmlparser/XMLParser.js
var XMLParser;
var init_XMLParser = __esm({
  "node_modules/fast-xml-parser/src/xmlparser/XMLParser.js"() {
    init_OptionsBuilder();
    init_OrderedObjParser();
    init_node2json();
    init_validator();
    init_xmlNode();
    XMLParser = class {
      constructor(options) {
        this.externalEntities = {};
        this.options = buildOptions(options);
      }
      /**
       * Parse XML dats to JS object 
       * @param {string|Buffer} xmlData 
       * @param {boolean|Object} validationOption 
       */
      parse(xmlData, validationOption) {
        if (typeof xmlData === "string") {
        } else if (xmlData.toString) {
          xmlData = xmlData.toString();
        } else {
          throw new Error("XML data is accepted in String or Bytes[] form.");
        }
        if (validationOption) {
          if (validationOption === true) validationOption = {};
          const result = validate(xmlData, validationOption);
          if (result !== true) {
            throw Error(`${result.err.msg}:${result.err.line}:${result.err.col}`);
          }
        }
        const orderedObjParser = new OrderedObjParser(this.options);
        orderedObjParser.addExternalEntities(this.externalEntities);
        const orderedResult = orderedObjParser.parseXml(xmlData);
        if (this.options.preserveOrder || orderedResult === void 0) return orderedResult;
        else return prettify(orderedResult, this.options);
      }
      /**
       * Add Entity which is not by default supported by this library
       * @param {string} key 
       * @param {string} value 
       */
      addEntity(key, value) {
        if (value.indexOf("&") !== -1) {
          throw new Error("Entity value can't have '&'");
        } else if (key.indexOf("&") !== -1 || key.indexOf(";") !== -1) {
          throw new Error("An entity must be set without '&' and ';'. Eg. use '#xD' for '&#xD;'");
        } else if (value === "&") {
          throw new Error("An entity with value '&' is not permitted");
        } else {
          this.externalEntities[key] = value;
        }
      }
      /**
       * Returns a Symbol that can be used to access the metadata
       * property on a node.
       * 
       * If Symbol is not available in the environment, an ordinary property is used
       * and the name of the property is here returned.
       * 
       * The XMLMetaData property is only present when `captureMetaData`
       * is true in the options.
       */
      static getMetaDataSymbol() {
        return XmlNode.getMetaDataSymbol();
      }
    };
  }
});

// node_modules/fast-xml-parser/src/fxp.js
var init_fxp = __esm({
  "node_modules/fast-xml-parser/src/fxp.js"() {
    "use strict";
    init_XMLParser();
  }
});

// node_modules/@aws-sdk/xml-builder/dist-es/xml-parser.js
function parseXML(xmlString) {
  return parser.parse(xmlString, true);
}
var parser;
var init_xml_parser = __esm({
  "node_modules/@aws-sdk/xml-builder/dist-es/xml-parser.js"() {
    init_fxp();
    parser = new XMLParser({
      attributeNamePrefix: "",
      htmlEntities: true,
      ignoreAttributes: false,
      ignoreDeclaration: true,
      parseTagValue: false,
      trimValues: false,
      tagValueProcessor: (_, val) => val.trim() === "" && val.includes("\n") ? "" : void 0
    });
    parser.addEntity("#xD", "\r");
    parser.addEntity("#10", "\n");
  }
});

// node_modules/@aws-sdk/xml-builder/dist-es/index.js
var init_dist_es28 = __esm({
  "node_modules/@aws-sdk/xml-builder/dist-es/index.js"() {
    init_XmlNode();
    init_XmlText();
    init_xml_parser();
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/xml/XmlShapeDeserializer.js
var XmlShapeDeserializer;
var init_XmlShapeDeserializer = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/protocols/xml/XmlShapeDeserializer.js"() {
    init_dist_es28();
    init_protocols();
    init_schema2();
    init_dist_es27();
    init_dist_es10();
    init_ConfigurableSerdeContext();
    init_UnionSerde();
    XmlShapeDeserializer = class extends SerdeContextConfig {
      settings;
      stringDeserializer;
      constructor(settings) {
        super();
        this.settings = settings;
        this.stringDeserializer = new FromStringShapeDeserializer(settings);
      }
      setSerdeContext(serdeContext) {
        this.serdeContext = serdeContext;
        this.stringDeserializer.setSerdeContext(serdeContext);
      }
      read(schema, bytes, key) {
        const ns = NormalizedSchema.of(schema);
        const memberSchemas = ns.getMemberSchemas();
        const isEventPayload = ns.isStructSchema() && ns.isMemberSchema() && !!Object.values(memberSchemas).find((memberNs) => {
          return !!memberNs.getMemberTraits().eventPayload;
        });
        if (isEventPayload) {
          const output = {};
          const memberName = Object.keys(memberSchemas)[0];
          const eventMemberSchema = memberSchemas[memberName];
          if (eventMemberSchema.isBlobSchema()) {
            output[memberName] = bytes;
          } else {
            output[memberName] = this.read(memberSchemas[memberName], bytes);
          }
          return output;
        }
        const xmlString = (this.serdeContext?.utf8Encoder ?? toUtf8)(bytes);
        const parsedObject = this.parseXml(xmlString);
        return this.readSchema(schema, key ? parsedObject[key] : parsedObject);
      }
      readSchema(_schema, value) {
        const ns = NormalizedSchema.of(_schema);
        if (ns.isUnitSchema()) {
          return;
        }
        const traits = ns.getMergedTraits();
        if (ns.isListSchema() && !Array.isArray(value)) {
          return this.readSchema(ns, [value]);
        }
        if (value == null) {
          return value;
        }
        if (typeof value === "object") {
          const sparse = !!traits.sparse;
          const flat = !!traits.xmlFlattened;
          if (ns.isListSchema()) {
            const listValue = ns.getValueSchema();
            const buffer2 = [];
            const sourceKey = listValue.getMergedTraits().xmlName ?? "member";
            const source = flat ? value : (value[0] ?? value)[sourceKey];
            const sourceArray = Array.isArray(source) ? source : [source];
            for (const v7 of sourceArray) {
              if (v7 != null || sparse) {
                buffer2.push(this.readSchema(listValue, v7));
              }
            }
            return buffer2;
          }
          const buffer = {};
          if (ns.isMapSchema()) {
            const keyNs = ns.getKeySchema();
            const memberNs = ns.getValueSchema();
            let entries;
            if (flat) {
              entries = Array.isArray(value) ? value : [value];
            } else {
              entries = Array.isArray(value.entry) ? value.entry : [value.entry];
            }
            const keyProperty = keyNs.getMergedTraits().xmlName ?? "key";
            const valueProperty = memberNs.getMergedTraits().xmlName ?? "value";
            for (const entry of entries) {
              const key = entry[keyProperty];
              const value2 = entry[valueProperty];
              if (value2 != null || sparse) {
                buffer[key] = this.readSchema(memberNs, value2);
              }
            }
            return buffer;
          }
          if (ns.isStructSchema()) {
            const union = ns.isUnionSchema();
            let unionSerde;
            if (union) {
              unionSerde = new UnionSerde(value, buffer);
            }
            for (const [memberName, memberSchema] of ns.structIterator()) {
              const memberTraits = memberSchema.getMergedTraits();
              const xmlObjectKey = !memberTraits.httpPayload ? memberSchema.getMemberTraits().xmlName ?? memberName : memberTraits.xmlName ?? memberSchema.getName();
              if (union) {
                unionSerde.mark(xmlObjectKey);
              }
              if (value[xmlObjectKey] != null) {
                buffer[memberName] = this.readSchema(memberSchema, value[xmlObjectKey]);
              }
            }
            if (union) {
              unionSerde.writeUnknown();
            }
            return buffer;
          }
          if (ns.isDocumentSchema()) {
            return value;
          }
          throw new Error(`@aws-sdk/core/protocols - xml deserializer unhandled schema type for ${ns.getName(true)}`);
        }
        if (ns.isListSchema()) {
          return [];
        }
        if (ns.isMapSchema() || ns.isStructSchema()) {
          return {};
        }
        return this.stringDeserializer.read(ns, value);
      }
      parseXml(xml) {
        if (xml.length) {
          let parsedObj;
          try {
            parsedObj = parseXML(xml);
          } catch (e6) {
            if (e6 && typeof e6 === "object") {
              Object.defineProperty(e6, "$responseBodyText", {
                value: xml
              });
            }
            throw e6;
          }
          const textNodeName = "#text";
          const key = Object.keys(parsedObj)[0];
          const parsedObjToReturn = parsedObj[key];
          if (parsedObjToReturn[textNodeName]) {
            parsedObjToReturn[key] = parsedObjToReturn[textNodeName];
            delete parsedObjToReturn[textNodeName];
          }
          return getValueFromTextNode(parsedObjToReturn);
        }
        return {};
      }
    };
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/query/QueryShapeSerializer.js
var QueryShapeSerializer;
var init_QueryShapeSerializer = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/protocols/query/QueryShapeSerializer.js"() {
    init_protocols();
    init_schema2();
    init_serde2();
    init_dist_es27();
    init_dist_es11();
    init_ConfigurableSerdeContext();
    init_structIterator();
    QueryShapeSerializer = class extends SerdeContextConfig {
      settings;
      buffer;
      constructor(settings) {
        super();
        this.settings = settings;
      }
      write(schema, value, prefix = "") {
        if (this.buffer === void 0) {
          this.buffer = "";
        }
        const ns = NormalizedSchema.of(schema);
        if (prefix && !prefix.endsWith(".")) {
          prefix += ".";
        }
        if (ns.isBlobSchema()) {
          if (typeof value === "string" || value instanceof Uint8Array) {
            this.writeKey(prefix);
            this.writeValue((this.serdeContext?.base64Encoder ?? toBase64)(value));
          }
        } else if (ns.isBooleanSchema() || ns.isNumericSchema() || ns.isStringSchema()) {
          if (value != null) {
            this.writeKey(prefix);
            this.writeValue(String(value));
          } else if (ns.isIdempotencyToken()) {
            this.writeKey(prefix);
            this.writeValue(v4());
          }
        } else if (ns.isBigIntegerSchema()) {
          if (value != null) {
            this.writeKey(prefix);
            this.writeValue(String(value));
          }
        } else if (ns.isBigDecimalSchema()) {
          if (value != null) {
            this.writeKey(prefix);
            this.writeValue(value instanceof NumericValue ? value.string : String(value));
          }
        } else if (ns.isTimestampSchema()) {
          if (value instanceof Date) {
            this.writeKey(prefix);
            const format2 = determineTimestampFormat(ns, this.settings);
            switch (format2) {
              case 5:
                this.writeValue(value.toISOString().replace(".000Z", "Z"));
                break;
              case 6:
                this.writeValue(dateToUtcString(value));
                break;
              case 7:
                this.writeValue(String(value.getTime() / 1e3));
                break;
            }
          }
        } else if (ns.isDocumentSchema()) {
          if (Array.isArray(value)) {
            this.write(64 | 15, value, prefix);
          } else if (value instanceof Date) {
            this.write(4, value, prefix);
          } else if (value instanceof Uint8Array) {
            this.write(21, value, prefix);
          } else if (value && typeof value === "object") {
            this.write(128 | 15, value, prefix);
          } else {
            this.writeKey(prefix);
            this.writeValue(String(value));
          }
        } else if (ns.isListSchema()) {
          if (Array.isArray(value)) {
            if (value.length === 0) {
              if (this.settings.serializeEmptyLists) {
                this.writeKey(prefix);
                this.writeValue("");
              }
            } else {
              const member2 = ns.getValueSchema();
              const flat = this.settings.flattenLists || ns.getMergedTraits().xmlFlattened;
              let i6 = 1;
              for (const item of value) {
                if (item == null) {
                  continue;
                }
                const suffix = this.getKey("member", member2.getMergedTraits().xmlName);
                const key = flat ? `${prefix}${i6}` : `${prefix}${suffix}.${i6}`;
                this.write(member2, item, key);
                ++i6;
              }
            }
          }
        } else if (ns.isMapSchema()) {
          if (value && typeof value === "object") {
            const keySchema = ns.getKeySchema();
            const memberSchema = ns.getValueSchema();
            const flat = ns.getMergedTraits().xmlFlattened;
            let i6 = 1;
            for (const [k6, v7] of Object.entries(value)) {
              if (v7 == null) {
                continue;
              }
              const keySuffix = this.getKey("key", keySchema.getMergedTraits().xmlName);
              const key = flat ? `${prefix}${i6}.${keySuffix}` : `${prefix}entry.${i6}.${keySuffix}`;
              const valueSuffix = this.getKey("value", memberSchema.getMergedTraits().xmlName);
              const valueKey = flat ? `${prefix}${i6}.${valueSuffix}` : `${prefix}entry.${i6}.${valueSuffix}`;
              this.write(keySchema, k6, key);
              this.write(memberSchema, v7, valueKey);
              ++i6;
            }
          }
        } else if (ns.isStructSchema()) {
          if (value && typeof value === "object") {
            let didWriteMember = false;
            for (const [memberName, member2] of serializingStructIterator(ns, value)) {
              if (value[memberName] == null && !member2.isIdempotencyToken()) {
                continue;
              }
              const suffix = this.getKey(memberName, member2.getMergedTraits().xmlName);
              const key = `${prefix}${suffix}`;
              this.write(member2, value[memberName], key);
              didWriteMember = true;
            }
            if (!didWriteMember && ns.isUnionSchema()) {
              const { $unknown } = value;
              if (Array.isArray($unknown)) {
                const [k6, v7] = $unknown;
                const key = `${prefix}${k6}`;
                this.write(15, v7, key);
              }
            }
          }
        } else if (ns.isUnitSchema()) {
        } else {
          throw new Error(`@aws-sdk/core/protocols - QuerySerializer unrecognized schema type ${ns.getName(true)}`);
        }
      }
      flush() {
        if (this.buffer === void 0) {
          throw new Error("@aws-sdk/core/protocols - QuerySerializer cannot flush with nothing written to buffer.");
        }
        const str = this.buffer;
        delete this.buffer;
        return str;
      }
      getKey(memberName, xmlName) {
        const key = xmlName ?? memberName;
        if (this.settings.capitalizeKeys) {
          return key[0].toUpperCase() + key.slice(1);
        }
        return key;
      }
      writeKey(key) {
        if (key.endsWith(".")) {
          key = key.slice(0, key.length - 1);
        }
        this.buffer += `&${extendedEncodeURIComponent(key)}=`;
      }
      writeValue(value) {
        this.buffer += extendedEncodeURIComponent(value);
      }
    };
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/query/AwsQueryProtocol.js
var AwsQueryProtocol;
var init_AwsQueryProtocol = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/protocols/query/AwsQueryProtocol.js"() {
    init_protocols();
    init_schema2();
    init_ProtocolLib();
    init_XmlShapeDeserializer();
    init_QueryShapeSerializer();
    AwsQueryProtocol = class extends RpcProtocol {
      options;
      serializer;
      deserializer;
      mixin = new ProtocolLib();
      constructor(options) {
        super({
          defaultNamespace: options.defaultNamespace
        });
        this.options = options;
        const settings = {
          timestampFormat: {
            useTrait: true,
            default: 5
          },
          httpBindings: false,
          xmlNamespace: options.xmlNamespace,
          serviceNamespace: options.defaultNamespace,
          serializeEmptyLists: true
        };
        this.serializer = new QueryShapeSerializer(settings);
        this.deserializer = new XmlShapeDeserializer(settings);
      }
      getShapeId() {
        return "aws.protocols#awsQuery";
      }
      setSerdeContext(serdeContext) {
        this.serializer.setSerdeContext(serdeContext);
        this.deserializer.setSerdeContext(serdeContext);
      }
      getPayloadCodec() {
        throw new Error("AWSQuery protocol has no payload codec.");
      }
      async serializeRequest(operationSchema, input, context) {
        const request2 = await super.serializeRequest(operationSchema, input, context);
        if (!request2.path.endsWith("/")) {
          request2.path += "/";
        }
        Object.assign(request2.headers, {
          "content-type": `application/x-www-form-urlencoded`
        });
        if (deref(operationSchema.input) === "unit" || !request2.body) {
          request2.body = "";
        }
        const action = operationSchema.name.split("#")[1] ?? operationSchema.name;
        request2.body = `Action=${action}&Version=${this.options.version}` + request2.body;
        if (request2.body.endsWith("&")) {
          request2.body = request2.body.slice(-1);
        }
        return request2;
      }
      async deserializeResponse(operationSchema, context, response) {
        const deserializer = this.deserializer;
        const ns = NormalizedSchema.of(operationSchema.output);
        const dataObject = {};
        if (response.statusCode >= 300) {
          const bytes2 = await collectBody(response.body, context);
          if (bytes2.byteLength > 0) {
            Object.assign(dataObject, await deserializer.read(15, bytes2));
          }
          await this.handleError(operationSchema, context, response, dataObject, this.deserializeMetadata(response));
        }
        for (const header in response.headers) {
          const value = response.headers[header];
          delete response.headers[header];
          response.headers[header.toLowerCase()] = value;
        }
        const shortName = operationSchema.name.split("#")[1] ?? operationSchema.name;
        const awsQueryResultKey = ns.isStructSchema() && this.useNestedResult() ? shortName + "Result" : void 0;
        const bytes = await collectBody(response.body, context);
        if (bytes.byteLength > 0) {
          Object.assign(dataObject, await deserializer.read(ns, bytes, awsQueryResultKey));
        }
        const output = {
          $metadata: this.deserializeMetadata(response),
          ...dataObject
        };
        return output;
      }
      useNestedResult() {
        return true;
      }
      async handleError(operationSchema, context, response, dataObject, metadata) {
        const errorIdentifier = this.loadQueryErrorCode(response, dataObject) ?? "Unknown";
        const errorData = this.loadQueryError(dataObject);
        const message = this.loadQueryErrorMessage(dataObject);
        errorData.message = message;
        errorData.Error = {
          Type: errorData.Type,
          Code: errorData.Code,
          Message: message
        };
        const { errorSchema, errorMetadata } = await this.mixin.getErrorSchemaOrThrowBaseException(errorIdentifier, this.options.defaultNamespace, response, errorData, metadata, this.mixin.findQueryCompatibleError);
        const ns = NormalizedSchema.of(errorSchema);
        const ErrorCtor = TypeRegistry.for(errorSchema[1]).getErrorCtor(errorSchema) ?? Error;
        const exception = new ErrorCtor(message);
        const output = {
          Type: errorData.Error.Type,
          Code: errorData.Error.Code,
          Error: errorData.Error
        };
        for (const [name, member2] of ns.structIterator()) {
          const target = member2.getMergedTraits().xmlName ?? name;
          const value = errorData[target] ?? dataObject[target];
          output[name] = this.deserializer.readSchema(member2, value);
        }
        throw this.mixin.decorateServiceException(Object.assign(exception, errorMetadata, {
          $fault: ns.getMergedTraits().error,
          message
        }, output), dataObject);
      }
      loadQueryErrorCode(output, data) {
        const code = (data.Errors?.[0]?.Error ?? data.Errors?.Error ?? data.Error)?.Code;
        if (code !== void 0) {
          return code;
        }
        if (output.statusCode == 404) {
          return "NotFound";
        }
      }
      loadQueryError(data) {
        return data.Errors?.[0]?.Error ?? data.Errors?.Error ?? data.Error;
      }
      loadQueryErrorMessage(data) {
        const errorData = this.loadQueryError(data);
        return errorData?.message ?? errorData?.Message ?? data.message ?? data.Message ?? "Unknown";
      }
      getDefaultContentType() {
        return "application/x-www-form-urlencoded";
      }
    };
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/query/AwsEc2QueryProtocol.js
var init_AwsEc2QueryProtocol = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/protocols/query/AwsEc2QueryProtocol.js"() {
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/xml/parseXmlBody.js
var init_parseXmlBody = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/protocols/xml/parseXmlBody.js"() {
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/xml/XmlShapeSerializer.js
var init_XmlShapeSerializer = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/protocols/xml/XmlShapeSerializer.js"() {
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/xml/XmlCodec.js
var init_XmlCodec = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/protocols/xml/XmlCodec.js"() {
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/xml/AwsRestXmlProtocol.js
var init_AwsRestXmlProtocol = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/protocols/xml/AwsRestXmlProtocol.js"() {
  }
});

// node_modules/@aws-sdk/core/dist-es/submodules/protocols/index.js
var init_protocols2 = __esm({
  "node_modules/@aws-sdk/core/dist-es/submodules/protocols/index.js"() {
    init_AwsSmithyRpcV2CborProtocol();
    init_coercing_serializers();
    init_AwsJson1_0Protocol();
    init_AwsJson1_1Protocol();
    init_AwsJsonRpcProtocol();
    init_AwsRestJsonProtocol();
    init_JsonCodec();
    init_JsonShapeDeserializer();
    init_JsonShapeSerializer();
    init_awsExpectUnion();
    init_parseJsonBody();
    init_AwsEc2QueryProtocol();
    init_AwsQueryProtocol();
    init_AwsRestXmlProtocol();
    init_XmlCodec();
    init_XmlShapeDeserializer();
    init_XmlShapeSerializer();
    init_parseXmlBody();
  }
});

// node_modules/@aws-sdk/core/dist-es/index.js
var init_dist_es29 = __esm({
  "node_modules/@aws-sdk/core/dist-es/index.js"() {
    init_client2();
    init_httpAuthSchemes2();
    init_protocols2();
  }
});

// node_modules/@aws-sdk/middleware-user-agent/dist-es/check-features.js
async function checkFeatures(context, config, args) {
  const request2 = args.request;
  if (request2?.headers?.["smithy-protocol"] === "rpc-v2-cbor") {
    setFeature2(context, "PROTOCOL_RPC_V2_CBOR", "M");
  }
  if (typeof config.retryStrategy === "function") {
    const retryStrategy = await config.retryStrategy();
    if (typeof retryStrategy.acquireInitialRetryToken === "function") {
      if (retryStrategy.constructor?.name?.includes("Adaptive")) {
        setFeature2(context, "RETRY_MODE_ADAPTIVE", "F");
      } else {
        setFeature2(context, "RETRY_MODE_STANDARD", "E");
      }
    } else {
      setFeature2(context, "RETRY_MODE_LEGACY", "D");
    }
  }
  if (typeof config.accountIdEndpointMode === "function") {
    const endpointV2 = context.endpointV2;
    if (String(endpointV2?.url?.hostname).match(ACCOUNT_ID_ENDPOINT_REGEX)) {
      setFeature2(context, "ACCOUNT_ID_ENDPOINT", "O");
    }
    switch (await config.accountIdEndpointMode?.()) {
      case "disabled":
        setFeature2(context, "ACCOUNT_ID_MODE_DISABLED", "Q");
        break;
      case "preferred":
        setFeature2(context, "ACCOUNT_ID_MODE_PREFERRED", "P");
        break;
      case "required":
        setFeature2(context, "ACCOUNT_ID_MODE_REQUIRED", "R");
        break;
    }
  }
  const identity = context.__smithy_context?.selectedHttpAuthScheme?.identity;
  if (identity?.$source) {
    const credentials = identity;
    if (credentials.accountId) {
      setFeature2(context, "RESOLVED_ACCOUNT_ID", "T");
    }
    for (const [key, value] of Object.entries(credentials.$source ?? {})) {
      setFeature2(context, key, value);
    }
  }
}
var ACCOUNT_ID_ENDPOINT_REGEX;
var init_check_features = __esm({
  "node_modules/@aws-sdk/middleware-user-agent/dist-es/check-features.js"() {
    init_dist_es29();
    ACCOUNT_ID_ENDPOINT_REGEX = /\d{12}\.ddb/;
  }
});

// node_modules/@aws-sdk/middleware-user-agent/dist-es/constants.js
var USER_AGENT, X_AMZ_USER_AGENT, SPACE, UA_NAME_SEPARATOR, UA_NAME_ESCAPE_REGEX, UA_VALUE_ESCAPE_REGEX, UA_ESCAPE_CHAR;
var init_constants4 = __esm({
  "node_modules/@aws-sdk/middleware-user-agent/dist-es/constants.js"() {
    USER_AGENT = "user-agent";
    X_AMZ_USER_AGENT = "x-amz-user-agent";
    SPACE = " ";
    UA_NAME_SEPARATOR = "/";
    UA_NAME_ESCAPE_REGEX = /[^!$%&'*+\-.^_`|~\w]/g;
    UA_VALUE_ESCAPE_REGEX = /[^!$%&'*+\-.^_`|~\w#]/g;
    UA_ESCAPE_CHAR = "-";
  }
});

// node_modules/@aws-sdk/middleware-user-agent/dist-es/encode-features.js
function encodeFeatures(features) {
  let buffer = "";
  for (const key in features) {
    const val = features[key];
    if (buffer.length + val.length + 1 <= BYTE_LIMIT) {
      if (buffer.length) {
        buffer += "," + val;
      } else {
        buffer += val;
      }
      continue;
    }
    break;
  }
  return buffer;
}
var BYTE_LIMIT;
var init_encode_features = __esm({
  "node_modules/@aws-sdk/middleware-user-agent/dist-es/encode-features.js"() {
    BYTE_LIMIT = 1024;
  }
});

// node_modules/@aws-sdk/middleware-user-agent/dist-es/user-agent-middleware.js
var userAgentMiddleware, escapeUserAgent, getUserAgentMiddlewareOptions, getUserAgentPlugin;
var init_user_agent_middleware = __esm({
  "node_modules/@aws-sdk/middleware-user-agent/dist-es/user-agent-middleware.js"() {
    init_dist_es23();
    init_dist_es2();
    init_check_features();
    init_constants4();
    init_encode_features();
    userAgentMiddleware = (options) => (next, context) => async (args) => {
      const { request: request2 } = args;
      if (!HttpRequest.isInstance(request2)) {
        return next(args);
      }
      const { headers } = request2;
      const userAgent = context?.userAgent?.map(escapeUserAgent) || [];
      const defaultUserAgent = (await options.defaultUserAgentProvider()).map(escapeUserAgent);
      await checkFeatures(context, options, args);
      const awsContext = context;
      defaultUserAgent.push(`m/${encodeFeatures(Object.assign({}, context.__smithy_context?.features, awsContext.__aws_sdk_context?.features))}`);
      const customUserAgent = options?.customUserAgent?.map(escapeUserAgent) || [];
      const appId = await options.userAgentAppId();
      if (appId) {
        defaultUserAgent.push(escapeUserAgent([`app`, `${appId}`]));
      }
      const prefix = getUserAgentPrefix();
      const sdkUserAgentValue = (prefix ? [prefix] : []).concat([...defaultUserAgent, ...userAgent, ...customUserAgent]).join(SPACE);
      const normalUAValue = [
        ...defaultUserAgent.filter((section) => section.startsWith("aws-sdk-")),
        ...customUserAgent
      ].join(SPACE);
      if (options.runtime !== "browser") {
        if (normalUAValue) {
          headers[X_AMZ_USER_AGENT] = headers[X_AMZ_USER_AGENT] ? `${headers[USER_AGENT]} ${normalUAValue}` : normalUAValue;
        }
        headers[USER_AGENT] = sdkUserAgentValue;
      } else {
        headers[X_AMZ_USER_AGENT] = sdkUserAgentValue;
      }
      return next({
        ...args,
        request: request2
      });
    };
    escapeUserAgent = (userAgentPair) => {
      const name = userAgentPair[0].split(UA_NAME_SEPARATOR).map((part) => part.replace(UA_NAME_ESCAPE_REGEX, UA_ESCAPE_CHAR)).join(UA_NAME_SEPARATOR);
      const version = userAgentPair[1]?.replace(UA_VALUE_ESCAPE_REGEX, UA_ESCAPE_CHAR);
      const prefixSeparatorIndex = name.indexOf(UA_NAME_SEPARATOR);
      const prefix = name.substring(0, prefixSeparatorIndex);
      let uaName = name.substring(prefixSeparatorIndex + 1);
      if (prefix === "api") {
        uaName = uaName.toLowerCase();
      }
      return [prefix, uaName, version].filter((item) => item && item.length > 0).reduce((acc, item, index) => {
        switch (index) {
          case 0:
            return item;
          case 1:
            return `${acc}/${item}`;
          default:
            return `${acc}#${item}`;
        }
      }, "");
    };
    getUserAgentMiddlewareOptions = {
      name: "getUserAgentMiddleware",
      step: "build",
      priority: "low",
      tags: ["SET_USER_AGENT", "USER_AGENT"],
      override: true
    };
    getUserAgentPlugin = (config) => ({
      applyToStack: (clientStack) => {
        clientStack.add(userAgentMiddleware(config), getUserAgentMiddlewareOptions);
      }
    });
  }
});

// node_modules/@aws-sdk/middleware-user-agent/dist-es/index.js
var init_dist_es30 = __esm({
  "node_modules/@aws-sdk/middleware-user-agent/dist-es/index.js"() {
    init_configurations();
    init_user_agent_middleware();
  }
});

// node_modules/@smithy/util-config-provider/dist-es/booleanSelector.js
var booleanSelector;
var init_booleanSelector = __esm({
  "node_modules/@smithy/util-config-provider/dist-es/booleanSelector.js"() {
    booleanSelector = (obj, key, type) => {
      if (!(key in obj))
        return void 0;
      if (obj[key] === "true")
        return true;
      if (obj[key] === "false")
        return false;
      throw new Error(`Cannot load ${type} "${key}". Expected "true" or "false", got ${obj[key]}.`);
    };
  }
});

// node_modules/@smithy/util-config-provider/dist-es/numberSelector.js
var init_numberSelector = __esm({
  "node_modules/@smithy/util-config-provider/dist-es/numberSelector.js"() {
  }
});

// node_modules/@smithy/util-config-provider/dist-es/types.js
var SelectorType;
var init_types4 = __esm({
  "node_modules/@smithy/util-config-provider/dist-es/types.js"() {
    (function(SelectorType2) {
      SelectorType2["ENV"] = "env";
      SelectorType2["CONFIG"] = "shared config entry";
    })(SelectorType || (SelectorType = {}));
  }
});

// node_modules/@smithy/util-config-provider/dist-es/index.js
var init_dist_es31 = __esm({
  "node_modules/@smithy/util-config-provider/dist-es/index.js"() {
    init_booleanSelector();
    init_numberSelector();
    init_types4();
  }
});

// node_modules/@smithy/config-resolver/dist-es/endpointsConfig/NodeUseDualstackEndpointConfigOptions.js
var ENV_USE_DUALSTACK_ENDPOINT, CONFIG_USE_DUALSTACK_ENDPOINT, NODE_USE_DUALSTACK_ENDPOINT_CONFIG_OPTIONS;
var init_NodeUseDualstackEndpointConfigOptions = __esm({
  "node_modules/@smithy/config-resolver/dist-es/endpointsConfig/NodeUseDualstackEndpointConfigOptions.js"() {
    init_dist_es31();
    ENV_USE_DUALSTACK_ENDPOINT = "AWS_USE_DUALSTACK_ENDPOINT";
    CONFIG_USE_DUALSTACK_ENDPOINT = "use_dualstack_endpoint";
    NODE_USE_DUALSTACK_ENDPOINT_CONFIG_OPTIONS = {
      environmentVariableSelector: (env2) => booleanSelector(env2, ENV_USE_DUALSTACK_ENDPOINT, SelectorType.ENV),
      configFileSelector: (profile) => booleanSelector(profile, CONFIG_USE_DUALSTACK_ENDPOINT, SelectorType.CONFIG),
      default: false
    };
  }
});

// node_modules/@smithy/config-resolver/dist-es/endpointsConfig/NodeUseFipsEndpointConfigOptions.js
var ENV_USE_FIPS_ENDPOINT, CONFIG_USE_FIPS_ENDPOINT, NODE_USE_FIPS_ENDPOINT_CONFIG_OPTIONS;
var init_NodeUseFipsEndpointConfigOptions = __esm({
  "node_modules/@smithy/config-resolver/dist-es/endpointsConfig/NodeUseFipsEndpointConfigOptions.js"() {
    init_dist_es31();
    ENV_USE_FIPS_ENDPOINT = "AWS_USE_FIPS_ENDPOINT";
    CONFIG_USE_FIPS_ENDPOINT = "use_fips_endpoint";
    NODE_USE_FIPS_ENDPOINT_CONFIG_OPTIONS = {
      environmentVariableSelector: (env2) => booleanSelector(env2, ENV_USE_FIPS_ENDPOINT, SelectorType.ENV),
      configFileSelector: (profile) => booleanSelector(profile, CONFIG_USE_FIPS_ENDPOINT, SelectorType.CONFIG),
      default: false
    };
  }
});

// node_modules/@smithy/config-resolver/dist-es/endpointsConfig/resolveCustomEndpointsConfig.js
var init_resolveCustomEndpointsConfig = __esm({
  "node_modules/@smithy/config-resolver/dist-es/endpointsConfig/resolveCustomEndpointsConfig.js"() {
  }
});

// node_modules/@smithy/config-resolver/dist-es/endpointsConfig/resolveEndpointsConfig.js
var init_resolveEndpointsConfig = __esm({
  "node_modules/@smithy/config-resolver/dist-es/endpointsConfig/resolveEndpointsConfig.js"() {
  }
});

// node_modules/@smithy/config-resolver/dist-es/endpointsConfig/index.js
var init_endpointsConfig = __esm({
  "node_modules/@smithy/config-resolver/dist-es/endpointsConfig/index.js"() {
    init_NodeUseDualstackEndpointConfigOptions();
    init_NodeUseFipsEndpointConfigOptions();
    init_resolveCustomEndpointsConfig();
    init_resolveEndpointsConfig();
  }
});

// node_modules/@smithy/config-resolver/dist-es/regionConfig/config.js
var REGION_ENV_NAME, REGION_INI_NAME, NODE_REGION_CONFIG_OPTIONS, NODE_REGION_CONFIG_FILE_OPTIONS;
var init_config2 = __esm({
  "node_modules/@smithy/config-resolver/dist-es/regionConfig/config.js"() {
    REGION_ENV_NAME = "AWS_REGION";
    REGION_INI_NAME = "region";
    NODE_REGION_CONFIG_OPTIONS = {
      environmentVariableSelector: (env2) => env2[REGION_ENV_NAME],
      configFileSelector: (profile) => profile[REGION_INI_NAME],
      default: () => {
        throw new Error("Region is missing");
      }
    };
    NODE_REGION_CONFIG_FILE_OPTIONS = {
      preferredFile: "credentials"
    };
  }
});

// node_modules/@smithy/config-resolver/dist-es/regionConfig/checkRegion.js
var validRegions, checkRegion;
var init_checkRegion = __esm({
  "node_modules/@smithy/config-resolver/dist-es/regionConfig/checkRegion.js"() {
    init_dist_es20();
    validRegions = /* @__PURE__ */ new Set();
    checkRegion = (region, check = isValidHostLabel) => {
      if (!validRegions.has(region) && !check(region)) {
        if (region === "*") {
          console.warn(`@smithy/config-resolver WARN - Please use the caller region instead of "*". See "sigv4a" in https://github.com/aws/aws-sdk-js-v3/blob/main/supplemental-docs/CLIENTS.md.`);
        } else {
          throw new Error(`Region not accepted: region="${region}" is not a valid hostname component.`);
        }
      } else {
        validRegions.add(region);
      }
    };
  }
});

// node_modules/@smithy/config-resolver/dist-es/regionConfig/isFipsRegion.js
var isFipsRegion;
var init_isFipsRegion = __esm({
  "node_modules/@smithy/config-resolver/dist-es/regionConfig/isFipsRegion.js"() {
    isFipsRegion = (region) => typeof region === "string" && (region.startsWith("fips-") || region.endsWith("-fips"));
  }
});

// node_modules/@smithy/config-resolver/dist-es/regionConfig/getRealRegion.js
var getRealRegion;
var init_getRealRegion = __esm({
  "node_modules/@smithy/config-resolver/dist-es/regionConfig/getRealRegion.js"() {
    init_isFipsRegion();
    getRealRegion = (region) => isFipsRegion(region) ? ["fips-aws-global", "aws-fips"].includes(region) ? "us-east-1" : region.replace(/fips-(dkr-|prod-)?|-fips/, "") : region;
  }
});

// node_modules/@smithy/config-resolver/dist-es/regionConfig/resolveRegionConfig.js
var resolveRegionConfig;
var init_resolveRegionConfig = __esm({
  "node_modules/@smithy/config-resolver/dist-es/regionConfig/resolveRegionConfig.js"() {
    init_checkRegion();
    init_getRealRegion();
    init_isFipsRegion();
    resolveRegionConfig = (input) => {
      const { region, useFipsEndpoint } = input;
      if (!region) {
        throw new Error("Region is missing");
      }
      return Object.assign(input, {
        region: async () => {
          const providedRegion = typeof region === "function" ? await region() : region;
          const realRegion = getRealRegion(providedRegion);
          checkRegion(realRegion);
          return realRegion;
        },
        useFipsEndpoint: async () => {
          const providedRegion = typeof region === "string" ? region : await region();
          if (isFipsRegion(providedRegion)) {
            return true;
          }
          return typeof useFipsEndpoint !== "function" ? Promise.resolve(!!useFipsEndpoint) : useFipsEndpoint();
        }
      });
    };
  }
});

// node_modules/@smithy/config-resolver/dist-es/regionConfig/index.js
var init_regionConfig = __esm({
  "node_modules/@smithy/config-resolver/dist-es/regionConfig/index.js"() {
    init_config2();
    init_resolveRegionConfig();
  }
});

// node_modules/@smithy/config-resolver/dist-es/regionInfo/PartitionHash.js
var init_PartitionHash = __esm({
  "node_modules/@smithy/config-resolver/dist-es/regionInfo/PartitionHash.js"() {
  }
});

// node_modules/@smithy/config-resolver/dist-es/regionInfo/RegionHash.js
var init_RegionHash = __esm({
  "node_modules/@smithy/config-resolver/dist-es/regionInfo/RegionHash.js"() {
  }
});

// node_modules/@smithy/config-resolver/dist-es/regionInfo/getRegionInfo.js
var init_getRegionInfo = __esm({
  "node_modules/@smithy/config-resolver/dist-es/regionInfo/getRegionInfo.js"() {
  }
});

// node_modules/@smithy/config-resolver/dist-es/regionInfo/index.js
var init_regionInfo = __esm({
  "node_modules/@smithy/config-resolver/dist-es/regionInfo/index.js"() {
    init_PartitionHash();
    init_RegionHash();
    init_getRegionInfo();
  }
});

// node_modules/@smithy/config-resolver/dist-es/index.js
var init_dist_es32 = __esm({
  "node_modules/@smithy/config-resolver/dist-es/index.js"() {
    init_endpointsConfig();
    init_regionConfig();
    init_regionInfo();
  }
});

// node_modules/@smithy/middleware-content-length/dist-es/index.js
function contentLengthMiddleware(bodyLengthChecker) {
  return (next) => async (args) => {
    const request2 = args.request;
    if (HttpRequest.isInstance(request2)) {
      const { body, headers } = request2;
      if (body && Object.keys(headers).map((str) => str.toLowerCase()).indexOf(CONTENT_LENGTH_HEADER) === -1) {
        try {
          const length = bodyLengthChecker(body);
          request2.headers = {
            ...request2.headers,
            [CONTENT_LENGTH_HEADER]: String(length)
          };
        } catch (error) {
        }
      }
    }
    return next({
      ...args,
      request: request2
    });
  };
}
var CONTENT_LENGTH_HEADER, contentLengthMiddlewareOptions, getContentLengthPlugin;
var init_dist_es33 = __esm({
  "node_modules/@smithy/middleware-content-length/dist-es/index.js"() {
    init_dist_es2();
    CONTENT_LENGTH_HEADER = "content-length";
    contentLengthMiddlewareOptions = {
      step: "build",
      tags: ["SET_CONTENT_LENGTH", "CONTENT_LENGTH"],
      name: "contentLengthMiddleware",
      override: true
    };
    getContentLengthPlugin = (options) => ({
      applyToStack: (clientStack) => {
        clientStack.add(contentLengthMiddleware(options.bodyLengthChecker), contentLengthMiddlewareOptions);
      }
    });
  }
});

// node_modules/@smithy/middleware-endpoint/dist-es/service-customizations/s3.js
var resolveParamsForS3, DOMAIN_PATTERN, IP_ADDRESS_PATTERN, DOTS_PATTERN, isDnsCompatibleBucketName, isArnBucketName;
var init_s3 = __esm({
  "node_modules/@smithy/middleware-endpoint/dist-es/service-customizations/s3.js"() {
    resolveParamsForS3 = async (endpointParams) => {
      const bucket = endpointParams?.Bucket || "";
      if (typeof endpointParams.Bucket === "string") {
        endpointParams.Bucket = bucket.replace(/#/g, encodeURIComponent("#")).replace(/\?/g, encodeURIComponent("?"));
      }
      if (isArnBucketName(bucket)) {
        if (endpointParams.ForcePathStyle === true) {
          throw new Error("Path-style addressing cannot be used with ARN buckets");
        }
      } else if (!isDnsCompatibleBucketName(bucket) || bucket.indexOf(".") !== -1 && !String(endpointParams.Endpoint).startsWith("http:") || bucket.toLowerCase() !== bucket || bucket.length < 3) {
        endpointParams.ForcePathStyle = true;
      }
      if (endpointParams.DisableMultiRegionAccessPoints) {
        endpointParams.disableMultiRegionAccessPoints = true;
        endpointParams.DisableMRAP = true;
      }
      return endpointParams;
    };
    DOMAIN_PATTERN = /^[a-z0-9][a-z0-9\.\-]{1,61}[a-z0-9]$/;
    IP_ADDRESS_PATTERN = /(\d+\.){3}\d+/;
    DOTS_PATTERN = /\.\./;
    isDnsCompatibleBucketName = (bucketName) => DOMAIN_PATTERN.test(bucketName) && !IP_ADDRESS_PATTERN.test(bucketName) && !DOTS_PATTERN.test(bucketName);
    isArnBucketName = (bucketName) => {
      const [arn, partition2, service, , , bucket] = bucketName.split(":");
      const isArn = arn === "arn" && bucketName.split(":").length >= 6;
      const isValidArn = Boolean(isArn && partition2 && service && bucket);
      if (isArn && !isValidArn) {
        throw new Error(`Invalid ARN: ${bucketName} was an invalid ARN.`);
      }
      return isValidArn;
    };
  }
});

// node_modules/@smithy/middleware-endpoint/dist-es/service-customizations/index.js
var init_service_customizations = __esm({
  "node_modules/@smithy/middleware-endpoint/dist-es/service-customizations/index.js"() {
    init_s3();
  }
});

// node_modules/@smithy/middleware-endpoint/dist-es/adaptors/createConfigValueProvider.js
var createConfigValueProvider;
var init_createConfigValueProvider = __esm({
  "node_modules/@smithy/middleware-endpoint/dist-es/adaptors/createConfigValueProvider.js"() {
    createConfigValueProvider = (configKey, canonicalEndpointParamKey, config, isClientContextParam = false) => {
      const configProvider = async () => {
        let configValue;
        if (isClientContextParam) {
          const clientContextParams = config.clientContextParams;
          const nestedValue = clientContextParams?.[configKey];
          configValue = nestedValue ?? config[configKey] ?? config[canonicalEndpointParamKey];
        } else {
          configValue = config[configKey] ?? config[canonicalEndpointParamKey];
        }
        if (typeof configValue === "function") {
          return configValue();
        }
        return configValue;
      };
      if (configKey === "credentialScope" || canonicalEndpointParamKey === "CredentialScope") {
        return async () => {
          const credentials = typeof config.credentials === "function" ? await config.credentials() : config.credentials;
          const configValue = credentials?.credentialScope ?? credentials?.CredentialScope;
          return configValue;
        };
      }
      if (configKey === "accountId" || canonicalEndpointParamKey === "AccountId") {
        return async () => {
          const credentials = typeof config.credentials === "function" ? await config.credentials() : config.credentials;
          const configValue = credentials?.accountId ?? credentials?.AccountId;
          return configValue;
        };
      }
      if (configKey === "endpoint" || canonicalEndpointParamKey === "endpoint") {
        return async () => {
          if (config.isCustomEndpoint === false) {
            return void 0;
          }
          const endpoint = await configProvider();
          if (endpoint && typeof endpoint === "object") {
            if ("url" in endpoint) {
              return endpoint.url.href;
            }
            if ("hostname" in endpoint) {
              const { protocol, hostname, port, path } = endpoint;
              return `${protocol}//${hostname}${port ? ":" + port : ""}${path}`;
            }
          }
          return endpoint;
        };
      }
      return configProvider;
    };
  }
});

// node_modules/@smithy/node-config-provider/dist-es/getSelectorName.js
function getSelectorName(functionString) {
  try {
    const constants = new Set(Array.from(functionString.match(/([A-Z_]){3,}/g) ?? []));
    constants.delete("CONFIG");
    constants.delete("CONFIG_PREFIX_SEPARATOR");
    constants.delete("ENV");
    return [...constants].join(", ");
  } catch (e6) {
    return functionString;
  }
}
var init_getSelectorName = __esm({
  "node_modules/@smithy/node-config-provider/dist-es/getSelectorName.js"() {
  }
});

// node_modules/@smithy/node-config-provider/dist-es/fromEnv.js
var fromEnv;
var init_fromEnv = __esm({
  "node_modules/@smithy/node-config-provider/dist-es/fromEnv.js"() {
    init_dist_es24();
    init_getSelectorName();
    fromEnv = (envVarSelector, options) => async () => {
      try {
        const config = envVarSelector(process.env, options);
        if (config === void 0) {
          throw new Error();
        }
        return config;
      } catch (e6) {
        throw new CredentialsProviderError(e6.message || `Not found in ENV: ${getSelectorName(envVarSelector.toString())}`, { logger: options?.logger });
      }
    };
  }
});

// node_modules/@smithy/shared-ini-file-loader/dist-es/getHomeDir.js
import { homedir } from "os";
import { sep } from "path";
var homeDirCache, getHomeDirCacheKey, getHomeDir;
var init_getHomeDir = __esm({
  "node_modules/@smithy/shared-ini-file-loader/dist-es/getHomeDir.js"() {
    homeDirCache = {};
    getHomeDirCacheKey = () => {
      if (process && process.geteuid) {
        return `${process.geteuid()}`;
      }
      return "DEFAULT";
    };
    getHomeDir = () => {
      const { HOME, USERPROFILE, HOMEPATH, HOMEDRIVE = `C:${sep}` } = process.env;
      if (HOME)
        return HOME;
      if (USERPROFILE)
        return USERPROFILE;
      if (HOMEPATH)
        return `${HOMEDRIVE}${HOMEPATH}`;
      const homeDirCacheKey = getHomeDirCacheKey();
      if (!homeDirCache[homeDirCacheKey])
        homeDirCache[homeDirCacheKey] = homedir();
      return homeDirCache[homeDirCacheKey];
    };
  }
});

// node_modules/@smithy/shared-ini-file-loader/dist-es/getProfileName.js
var ENV_PROFILE, DEFAULT_PROFILE, getProfileName;
var init_getProfileName = __esm({
  "node_modules/@smithy/shared-ini-file-loader/dist-es/getProfileName.js"() {
    ENV_PROFILE = "AWS_PROFILE";
    DEFAULT_PROFILE = "default";
    getProfileName = (init) => init.profile || process.env[ENV_PROFILE] || DEFAULT_PROFILE;
  }
});

// node_modules/@smithy/shared-ini-file-loader/dist-es/getSSOTokenFilepath.js
import { createHash } from "crypto";
import { join } from "path";
var getSSOTokenFilepath;
var init_getSSOTokenFilepath = __esm({
  "node_modules/@smithy/shared-ini-file-loader/dist-es/getSSOTokenFilepath.js"() {
    init_getHomeDir();
    getSSOTokenFilepath = (id) => {
      const hasher = createHash("sha1");
      const cacheName = hasher.update(id).digest("hex");
      return join(getHomeDir(), ".aws", "sso", "cache", `${cacheName}.json`);
    };
  }
});

// node_modules/@smithy/shared-ini-file-loader/dist-es/getSSOTokenFromFile.js
import { readFile } from "fs/promises";
var tokenIntercept, getSSOTokenFromFile;
var init_getSSOTokenFromFile = __esm({
  "node_modules/@smithy/shared-ini-file-loader/dist-es/getSSOTokenFromFile.js"() {
    init_getSSOTokenFilepath();
    tokenIntercept = {};
    getSSOTokenFromFile = async (id) => {
      if (tokenIntercept[id]) {
        return tokenIntercept[id];
      }
      const ssoTokenFilepath = getSSOTokenFilepath(id);
      const ssoTokenText = await readFile(ssoTokenFilepath, "utf8");
      return JSON.parse(ssoTokenText);
    };
  }
});

// node_modules/@smithy/shared-ini-file-loader/dist-es/constants.js
var CONFIG_PREFIX_SEPARATOR;
var init_constants5 = __esm({
  "node_modules/@smithy/shared-ini-file-loader/dist-es/constants.js"() {
    CONFIG_PREFIX_SEPARATOR = ".";
  }
});

// node_modules/@smithy/shared-ini-file-loader/dist-es/getConfigData.js
var getConfigData;
var init_getConfigData = __esm({
  "node_modules/@smithy/shared-ini-file-loader/dist-es/getConfigData.js"() {
    init_dist_es();
    init_constants5();
    getConfigData = (data) => Object.entries(data).filter(([key]) => {
      const indexOfSeparator = key.indexOf(CONFIG_PREFIX_SEPARATOR);
      if (indexOfSeparator === -1) {
        return false;
      }
      return Object.values(IniSectionType).includes(key.substring(0, indexOfSeparator));
    }).reduce((acc, [key, value]) => {
      const indexOfSeparator = key.indexOf(CONFIG_PREFIX_SEPARATOR);
      const updatedKey = key.substring(0, indexOfSeparator) === IniSectionType.PROFILE ? key.substring(indexOfSeparator + 1) : key;
      acc[updatedKey] = value;
      return acc;
    }, {
      ...data.default && { default: data.default }
    });
  }
});

// node_modules/@smithy/shared-ini-file-loader/dist-es/getConfigFilepath.js
import { join as join2 } from "path";
var ENV_CONFIG_PATH, getConfigFilepath;
var init_getConfigFilepath = __esm({
  "node_modules/@smithy/shared-ini-file-loader/dist-es/getConfigFilepath.js"() {
    init_getHomeDir();
    ENV_CONFIG_PATH = "AWS_CONFIG_FILE";
    getConfigFilepath = () => process.env[ENV_CONFIG_PATH] || join2(getHomeDir(), ".aws", "config");
  }
});

// node_modules/@smithy/shared-ini-file-loader/dist-es/getCredentialsFilepath.js
import { join as join3 } from "path";
var ENV_CREDENTIALS_PATH, getCredentialsFilepath;
var init_getCredentialsFilepath = __esm({
  "node_modules/@smithy/shared-ini-file-loader/dist-es/getCredentialsFilepath.js"() {
    init_getHomeDir();
    ENV_CREDENTIALS_PATH = "AWS_SHARED_CREDENTIALS_FILE";
    getCredentialsFilepath = () => process.env[ENV_CREDENTIALS_PATH] || join3(getHomeDir(), ".aws", "credentials");
  }
});

// node_modules/@smithy/shared-ini-file-loader/dist-es/parseIni.js
var prefixKeyRegex, profileNameBlockList, parseIni;
var init_parseIni = __esm({
  "node_modules/@smithy/shared-ini-file-loader/dist-es/parseIni.js"() {
    init_dist_es();
    init_constants5();
    prefixKeyRegex = /^([\w-]+)\s(["'])?([\w-@\+\.%:/]+)\2$/;
    profileNameBlockList = ["__proto__", "profile __proto__"];
    parseIni = (iniData) => {
      const map = {};
      let currentSection;
      let currentSubSection;
      for (const iniLine of iniData.split(/\r?\n/)) {
        const trimmedLine = iniLine.split(/(^|\s)[;#]/)[0].trim();
        const isSection = trimmedLine[0] === "[" && trimmedLine[trimmedLine.length - 1] === "]";
        if (isSection) {
          currentSection = void 0;
          currentSubSection = void 0;
          const sectionName = trimmedLine.substring(1, trimmedLine.length - 1);
          const matches = prefixKeyRegex.exec(sectionName);
          if (matches) {
            const [, prefix, , name] = matches;
            if (Object.values(IniSectionType).includes(prefix)) {
              currentSection = [prefix, name].join(CONFIG_PREFIX_SEPARATOR);
            }
          } else {
            currentSection = sectionName;
          }
          if (profileNameBlockList.includes(sectionName)) {
            throw new Error(`Found invalid profile name "${sectionName}"`);
          }
        } else if (currentSection) {
          const indexOfEqualsSign = trimmedLine.indexOf("=");
          if (![0, -1].includes(indexOfEqualsSign)) {
            const [name, value] = [
              trimmedLine.substring(0, indexOfEqualsSign).trim(),
              trimmedLine.substring(indexOfEqualsSign + 1).trim()
            ];
            if (value === "") {
              currentSubSection = name;
            } else {
              if (currentSubSection && iniLine.trimStart() === iniLine) {
                currentSubSection = void 0;
              }
              map[currentSection] = map[currentSection] || {};
              const key = currentSubSection ? [currentSubSection, name].join(CONFIG_PREFIX_SEPARATOR) : name;
              map[currentSection][key] = value;
            }
          }
        }
      }
      return map;
    };
  }
});

// node_modules/@smithy/shared-ini-file-loader/dist-es/readFile.js
import { readFile as fsReadFile } from "node:fs/promises";
var filePromises, fileIntercept, readFile2;
var init_readFile = __esm({
  "node_modules/@smithy/shared-ini-file-loader/dist-es/readFile.js"() {
    filePromises = {};
    fileIntercept = {};
    readFile2 = (path, options) => {
      if (fileIntercept[path] !== void 0) {
        return fileIntercept[path];
      }
      if (!filePromises[path] || options?.ignoreCache) {
        filePromises[path] = fsReadFile(path, "utf8");
      }
      return filePromises[path];
    };
  }
});

// node_modules/@smithy/shared-ini-file-loader/dist-es/loadSharedConfigFiles.js
import { join as join4 } from "path";
var swallowError, loadSharedConfigFiles;
var init_loadSharedConfigFiles = __esm({
  "node_modules/@smithy/shared-ini-file-loader/dist-es/loadSharedConfigFiles.js"() {
    init_getConfigData();
    init_getConfigFilepath();
    init_getCredentialsFilepath();
    init_getHomeDir();
    init_parseIni();
    init_readFile();
    init_constants5();
    swallowError = () => ({});
    loadSharedConfigFiles = async (init = {}) => {
      const { filepath = getCredentialsFilepath(), configFilepath = getConfigFilepath() } = init;
      const homeDir = getHomeDir();
      const relativeHomeDirPrefix = "~/";
      let resolvedFilepath = filepath;
      if (filepath.startsWith(relativeHomeDirPrefix)) {
        resolvedFilepath = join4(homeDir, filepath.slice(2));
      }
      let resolvedConfigFilepath = configFilepath;
      if (configFilepath.startsWith(relativeHomeDirPrefix)) {
        resolvedConfigFilepath = join4(homeDir, configFilepath.slice(2));
      }
      const parsedFiles = await Promise.all([
        readFile2(resolvedConfigFilepath, {
          ignoreCache: init.ignoreCache
        }).then(parseIni).then(getConfigData).catch(swallowError),
        readFile2(resolvedFilepath, {
          ignoreCache: init.ignoreCache
        }).then(parseIni).catch(swallowError)
      ]);
      return {
        configFile: parsedFiles[0],
        credentialsFile: parsedFiles[1]
      };
    };
  }
});

// node_modules/@smithy/shared-ini-file-loader/dist-es/getSsoSessionData.js
var getSsoSessionData;
var init_getSsoSessionData = __esm({
  "node_modules/@smithy/shared-ini-file-loader/dist-es/getSsoSessionData.js"() {
    init_dist_es();
    init_loadSharedConfigFiles();
    getSsoSessionData = (data) => Object.entries(data).filter(([key]) => key.startsWith(IniSectionType.SSO_SESSION + CONFIG_PREFIX_SEPARATOR)).reduce((acc, [key, value]) => ({ ...acc, [key.substring(key.indexOf(CONFIG_PREFIX_SEPARATOR) + 1)]: value }), {});
  }
});

// node_modules/@smithy/shared-ini-file-loader/dist-es/loadSsoSessionData.js
var swallowError2, loadSsoSessionData;
var init_loadSsoSessionData = __esm({
  "node_modules/@smithy/shared-ini-file-loader/dist-es/loadSsoSessionData.js"() {
    init_getConfigFilepath();
    init_getSsoSessionData();
    init_parseIni();
    init_readFile();
    swallowError2 = () => ({});
    loadSsoSessionData = async (init = {}) => readFile2(init.configFilepath ?? getConfigFilepath()).then(parseIni).then(getSsoSessionData).catch(swallowError2);
  }
});

// node_modules/@smithy/shared-ini-file-loader/dist-es/mergeConfigFiles.js
var mergeConfigFiles;
var init_mergeConfigFiles = __esm({
  "node_modules/@smithy/shared-ini-file-loader/dist-es/mergeConfigFiles.js"() {
    mergeConfigFiles = (...files) => {
      const merged = {};
      for (const file of files) {
        for (const [key, values] of Object.entries(file)) {
          if (merged[key] !== void 0) {
            Object.assign(merged[key], values);
          } else {
            merged[key] = values;
          }
        }
      }
      return merged;
    };
  }
});

// node_modules/@smithy/shared-ini-file-loader/dist-es/parseKnownFiles.js
var parseKnownFiles;
var init_parseKnownFiles = __esm({
  "node_modules/@smithy/shared-ini-file-loader/dist-es/parseKnownFiles.js"() {
    init_loadSharedConfigFiles();
    init_mergeConfigFiles();
    parseKnownFiles = async (init) => {
      const parsedFiles = await loadSharedConfigFiles(init);
      return mergeConfigFiles(parsedFiles.configFile, parsedFiles.credentialsFile);
    };
  }
});

// node_modules/@smithy/shared-ini-file-loader/dist-es/externalDataInterceptor.js
var externalDataInterceptor;
var init_externalDataInterceptor = __esm({
  "node_modules/@smithy/shared-ini-file-loader/dist-es/externalDataInterceptor.js"() {
    init_getSSOTokenFromFile();
    init_readFile();
    externalDataInterceptor = {
      getFileRecord() {
        return fileIntercept;
      },
      interceptFile(path, contents) {
        fileIntercept[path] = Promise.resolve(contents);
      },
      getTokenRecord() {
        return tokenIntercept;
      },
      interceptToken(id, contents) {
        tokenIntercept[id] = contents;
      }
    };
  }
});

// node_modules/@smithy/shared-ini-file-loader/dist-es/types.js
var init_types5 = __esm({
  "node_modules/@smithy/shared-ini-file-loader/dist-es/types.js"() {
  }
});

// node_modules/@smithy/shared-ini-file-loader/dist-es/index.js
var init_dist_es34 = __esm({
  "node_modules/@smithy/shared-ini-file-loader/dist-es/index.js"() {
    init_getHomeDir();
    init_getProfileName();
    init_getSSOTokenFilepath();
    init_getSSOTokenFromFile();
    init_loadSharedConfigFiles();
    init_loadSsoSessionData();
    init_parseKnownFiles();
    init_externalDataInterceptor();
    init_types5();
    init_readFile();
  }
});

// node_modules/@smithy/node-config-provider/dist-es/fromSharedConfigFiles.js
var fromSharedConfigFiles;
var init_fromSharedConfigFiles = __esm({
  "node_modules/@smithy/node-config-provider/dist-es/fromSharedConfigFiles.js"() {
    init_dist_es24();
    init_dist_es34();
    init_getSelectorName();
    fromSharedConfigFiles = (configSelector, { preferredFile = "config", ...init } = {}) => async () => {
      const profile = getProfileName(init);
      const { configFile, credentialsFile } = await loadSharedConfigFiles(init);
      const profileFromCredentials = credentialsFile[profile] || {};
      const profileFromConfig = configFile[profile] || {};
      const mergedProfile = preferredFile === "config" ? { ...profileFromCredentials, ...profileFromConfig } : { ...profileFromConfig, ...profileFromCredentials };
      try {
        const cfgFile = preferredFile === "config" ? configFile : credentialsFile;
        const configValue = configSelector(mergedProfile, cfgFile);
        if (configValue === void 0) {
          throw new Error();
        }
        return configValue;
      } catch (e6) {
        throw new CredentialsProviderError(e6.message || `Not found in config files w/ profile [${profile}]: ${getSelectorName(configSelector.toString())}`, { logger: init.logger });
      }
    };
  }
});

// node_modules/@smithy/node-config-provider/dist-es/fromStatic.js
var isFunction, fromStatic2;
var init_fromStatic2 = __esm({
  "node_modules/@smithy/node-config-provider/dist-es/fromStatic.js"() {
    init_dist_es24();
    isFunction = (func) => typeof func === "function";
    fromStatic2 = (defaultValue) => isFunction(defaultValue) ? async () => await defaultValue() : fromStatic(defaultValue);
  }
});

// node_modules/@smithy/node-config-provider/dist-es/configLoader.js
var loadConfig;
var init_configLoader = __esm({
  "node_modules/@smithy/node-config-provider/dist-es/configLoader.js"() {
    init_dist_es24();
    init_fromEnv();
    init_fromSharedConfigFiles();
    init_fromStatic2();
    loadConfig = ({ environmentVariableSelector, configFileSelector, default: defaultValue }, configuration = {}) => {
      const { signingName, logger: logger2 } = configuration;
      const envOptions = { signingName, logger: logger2 };
      return memoize(chain(fromEnv(environmentVariableSelector, envOptions), fromSharedConfigFiles(configFileSelector, configuration), fromStatic2(defaultValue)));
    };
  }
});

// node_modules/@smithy/node-config-provider/dist-es/index.js
var init_dist_es35 = __esm({
  "node_modules/@smithy/node-config-provider/dist-es/index.js"() {
    init_configLoader();
  }
});

// node_modules/@smithy/middleware-endpoint/dist-es/adaptors/getEndpointUrlConfig.js
var ENV_ENDPOINT_URL, CONFIG_ENDPOINT_URL, getEndpointUrlConfig;
var init_getEndpointUrlConfig = __esm({
  "node_modules/@smithy/middleware-endpoint/dist-es/adaptors/getEndpointUrlConfig.js"() {
    init_dist_es34();
    ENV_ENDPOINT_URL = "AWS_ENDPOINT_URL";
    CONFIG_ENDPOINT_URL = "endpoint_url";
    getEndpointUrlConfig = (serviceId) => ({
      environmentVariableSelector: (env2) => {
        const serviceSuffixParts = serviceId.split(" ").map((w6) => w6.toUpperCase());
        const serviceEndpointUrl = env2[[ENV_ENDPOINT_URL, ...serviceSuffixParts].join("_")];
        if (serviceEndpointUrl)
          return serviceEndpointUrl;
        const endpointUrl = env2[ENV_ENDPOINT_URL];
        if (endpointUrl)
          return endpointUrl;
        return void 0;
      },
      configFileSelector: (profile, config) => {
        if (config && profile.services) {
          const servicesSection = config[["services", profile.services].join(CONFIG_PREFIX_SEPARATOR)];
          if (servicesSection) {
            const servicePrefixParts = serviceId.split(" ").map((w6) => w6.toLowerCase());
            const endpointUrl2 = servicesSection[[servicePrefixParts.join("_"), CONFIG_ENDPOINT_URL].join(CONFIG_PREFIX_SEPARATOR)];
            if (endpointUrl2)
              return endpointUrl2;
          }
        }
        const endpointUrl = profile[CONFIG_ENDPOINT_URL];
        if (endpointUrl)
          return endpointUrl;
        return void 0;
      },
      default: void 0
    });
  }
});

// node_modules/@smithy/middleware-endpoint/dist-es/adaptors/getEndpointFromConfig.js
var getEndpointFromConfig;
var init_getEndpointFromConfig = __esm({
  "node_modules/@smithy/middleware-endpoint/dist-es/adaptors/getEndpointFromConfig.js"() {
    init_dist_es35();
    init_getEndpointUrlConfig();
    getEndpointFromConfig = async (serviceId) => loadConfig(getEndpointUrlConfig(serviceId ?? ""))();
  }
});

// node_modules/@smithy/middleware-endpoint/dist-es/adaptors/toEndpointV1.js
var toEndpointV1;
var init_toEndpointV1 = __esm({
  "node_modules/@smithy/middleware-endpoint/dist-es/adaptors/toEndpointV1.js"() {
    init_dist_es22();
    toEndpointV1 = (endpoint) => {
      if (typeof endpoint === "object") {
        if ("url" in endpoint) {
          return parseUrl(endpoint.url);
        }
        return endpoint;
      }
      return parseUrl(endpoint);
    };
  }
});

// node_modules/@smithy/middleware-endpoint/dist-es/adaptors/getEndpointFromInstructions.js
var getEndpointFromInstructions, resolveParams;
var init_getEndpointFromInstructions = __esm({
  "node_modules/@smithy/middleware-endpoint/dist-es/adaptors/getEndpointFromInstructions.js"() {
    init_service_customizations();
    init_createConfigValueProvider();
    init_getEndpointFromConfig();
    init_toEndpointV1();
    getEndpointFromInstructions = async (commandInput, instructionsSupplier, clientConfig, context) => {
      if (!clientConfig.isCustomEndpoint) {
        let endpointFromConfig;
        if (clientConfig.serviceConfiguredEndpoint) {
          endpointFromConfig = await clientConfig.serviceConfiguredEndpoint();
        } else {
          endpointFromConfig = await getEndpointFromConfig(clientConfig.serviceId);
        }
        if (endpointFromConfig) {
          clientConfig.endpoint = () => Promise.resolve(toEndpointV1(endpointFromConfig));
          clientConfig.isCustomEndpoint = true;
        }
      }
      const endpointParams = await resolveParams(commandInput, instructionsSupplier, clientConfig);
      if (typeof clientConfig.endpointProvider !== "function") {
        throw new Error("config.endpointProvider is not set.");
      }
      const endpoint = clientConfig.endpointProvider(endpointParams, context);
      return endpoint;
    };
    resolveParams = async (commandInput, instructionsSupplier, clientConfig) => {
      const endpointParams = {};
      const instructions = instructionsSupplier?.getEndpointParameterInstructions?.() || {};
      for (const [name, instruction] of Object.entries(instructions)) {
        switch (instruction.type) {
          case "staticContextParams":
            endpointParams[name] = instruction.value;
            break;
          case "contextParams":
            endpointParams[name] = commandInput[instruction.name];
            break;
          case "clientContextParams":
          case "builtInParams":
            endpointParams[name] = await createConfigValueProvider(instruction.name, name, clientConfig, instruction.type !== "builtInParams")();
            break;
          case "operationContextParams":
            endpointParams[name] = instruction.get(commandInput);
            break;
          default:
            throw new Error("Unrecognized endpoint parameter instruction: " + JSON.stringify(instruction));
        }
      }
      if (Object.keys(instructions).length === 0) {
        Object.assign(endpointParams, clientConfig);
      }
      if (String(clientConfig.serviceId).toLowerCase() === "s3") {
        await resolveParamsForS3(endpointParams);
      }
      return endpointParams;
    };
  }
});

// node_modules/@smithy/middleware-endpoint/dist-es/adaptors/index.js
var init_adaptors = __esm({
  "node_modules/@smithy/middleware-endpoint/dist-es/adaptors/index.js"() {
    init_getEndpointFromInstructions();
    init_toEndpointV1();
  }
});

// node_modules/@smithy/middleware-endpoint/dist-es/endpointMiddleware.js
var endpointMiddleware;
var init_endpointMiddleware = __esm({
  "node_modules/@smithy/middleware-endpoint/dist-es/endpointMiddleware.js"() {
    init_dist_es19();
    init_dist_es6();
    init_getEndpointFromInstructions();
    endpointMiddleware = ({ config, instructions }) => {
      return (next, context) => async (args) => {
        if (config.isCustomEndpoint) {
          setFeature(context, "ENDPOINT_OVERRIDE", "N");
        }
        const endpoint = await getEndpointFromInstructions(args.input, {
          getEndpointParameterInstructions() {
            return instructions;
          }
        }, { ...config }, context);
        context.endpointV2 = endpoint;
        context.authSchemes = endpoint.properties?.authSchemes;
        const authScheme = context.authSchemes?.[0];
        if (authScheme) {
          context["signing_region"] = authScheme.signingRegion;
          context["signing_service"] = authScheme.signingName;
          const smithyContext = getSmithyContext(context);
          const httpAuthOption = smithyContext?.selectedHttpAuthScheme?.httpAuthOption;
          if (httpAuthOption) {
            httpAuthOption.signingProperties = Object.assign(httpAuthOption.signingProperties || {}, {
              signing_region: authScheme.signingRegion,
              signingRegion: authScheme.signingRegion,
              signing_service: authScheme.signingName,
              signingName: authScheme.signingName,
              signingRegionSet: authScheme.signingRegionSet
            }, authScheme.properties);
          }
        }
        return next({
          ...args
        });
      };
    };
  }
});

// node_modules/@smithy/middleware-endpoint/dist-es/getEndpointPlugin.js
var endpointMiddlewareOptions, getEndpointPlugin;
var init_getEndpointPlugin = __esm({
  "node_modules/@smithy/middleware-endpoint/dist-es/getEndpointPlugin.js"() {
    init_dist_es7();
    init_endpointMiddleware();
    endpointMiddlewareOptions = {
      step: "serialize",
      tags: ["ENDPOINT_PARAMETERS", "ENDPOINT_V2", "ENDPOINT"],
      name: "endpointV2Middleware",
      override: true,
      relation: "before",
      toMiddleware: serializerMiddlewareOption.name
    };
    getEndpointPlugin = (config, instructions) => ({
      applyToStack: (clientStack) => {
        clientStack.addRelativeTo(endpointMiddleware({
          config,
          instructions
        }), endpointMiddlewareOptions);
      }
    });
  }
});

// node_modules/@smithy/middleware-endpoint/dist-es/resolveEndpointConfig.js
var resolveEndpointConfig;
var init_resolveEndpointConfig = __esm({
  "node_modules/@smithy/middleware-endpoint/dist-es/resolveEndpointConfig.js"() {
    init_dist_es6();
    init_getEndpointFromConfig();
    init_toEndpointV1();
    resolveEndpointConfig = (input) => {
      const tls = input.tls ?? true;
      const { endpoint, useDualstackEndpoint, useFipsEndpoint } = input;
      const customEndpointProvider = endpoint != null ? async () => toEndpointV1(await normalizeProvider(endpoint)()) : void 0;
      const isCustomEndpoint = !!endpoint;
      const resolvedConfig = Object.assign(input, {
        endpoint: customEndpointProvider,
        tls,
        isCustomEndpoint,
        useDualstackEndpoint: normalizeProvider(useDualstackEndpoint ?? false),
        useFipsEndpoint: normalizeProvider(useFipsEndpoint ?? false)
      });
      let configuredEndpointPromise = void 0;
      resolvedConfig.serviceConfiguredEndpoint = async () => {
        if (input.serviceId && !configuredEndpointPromise) {
          configuredEndpointPromise = getEndpointFromConfig(input.serviceId);
        }
        return configuredEndpointPromise;
      };
      return resolvedConfig;
    };
  }
});

// node_modules/@smithy/middleware-endpoint/dist-es/resolveEndpointRequiredConfig.js
var init_resolveEndpointRequiredConfig = __esm({
  "node_modules/@smithy/middleware-endpoint/dist-es/resolveEndpointRequiredConfig.js"() {
  }
});

// node_modules/@smithy/middleware-endpoint/dist-es/types.js
var init_types6 = __esm({
  "node_modules/@smithy/middleware-endpoint/dist-es/types.js"() {
  }
});

// node_modules/@smithy/middleware-endpoint/dist-es/index.js
var init_dist_es36 = __esm({
  "node_modules/@smithy/middleware-endpoint/dist-es/index.js"() {
    init_adaptors();
    init_endpointMiddleware();
    init_getEndpointPlugin();
    init_resolveEndpointConfig();
    init_resolveEndpointRequiredConfig();
    init_types6();
  }
});

// node_modules/@smithy/util-retry/dist-es/config.js
var RETRY_MODES, DEFAULT_MAX_ATTEMPTS, DEFAULT_RETRY_MODE;
var init_config3 = __esm({
  "node_modules/@smithy/util-retry/dist-es/config.js"() {
    (function(RETRY_MODES2) {
      RETRY_MODES2["STANDARD"] = "standard";
      RETRY_MODES2["ADAPTIVE"] = "adaptive";
    })(RETRY_MODES || (RETRY_MODES = {}));
    DEFAULT_MAX_ATTEMPTS = 3;
    DEFAULT_RETRY_MODE = RETRY_MODES.STANDARD;
  }
});

// node_modules/@smithy/service-error-classification/dist-es/constants.js
var THROTTLING_ERROR_CODES, TRANSIENT_ERROR_CODES, TRANSIENT_ERROR_STATUS_CODES, NODEJS_TIMEOUT_ERROR_CODES2, NODEJS_NETWORK_ERROR_CODES;
var init_constants6 = __esm({
  "node_modules/@smithy/service-error-classification/dist-es/constants.js"() {
    THROTTLING_ERROR_CODES = [
      "BandwidthLimitExceeded",
      "EC2ThrottledException",
      "LimitExceededException",
      "PriorRequestNotComplete",
      "ProvisionedThroughputExceededException",
      "RequestLimitExceeded",
      "RequestThrottled",
      "RequestThrottledException",
      "SlowDown",
      "ThrottledException",
      "Throttling",
      "ThrottlingException",
      "TooManyRequestsException",
      "TransactionInProgressException"
    ];
    TRANSIENT_ERROR_CODES = ["TimeoutError", "RequestTimeout", "RequestTimeoutException"];
    TRANSIENT_ERROR_STATUS_CODES = [500, 502, 503, 504];
    NODEJS_TIMEOUT_ERROR_CODES2 = ["ECONNRESET", "ECONNREFUSED", "EPIPE", "ETIMEDOUT"];
    NODEJS_NETWORK_ERROR_CODES = ["EHOSTUNREACH", "ENETUNREACH", "ENOTFOUND"];
  }
});

// node_modules/@smithy/service-error-classification/dist-es/index.js
var isRetryableByTrait, isClockSkewCorrectedError, isBrowserNetworkError, isThrottlingError, isTransientError, isServerError;
var init_dist_es37 = __esm({
  "node_modules/@smithy/service-error-classification/dist-es/index.js"() {
    init_constants6();
    isRetryableByTrait = (error) => error?.$retryable !== void 0;
    isClockSkewCorrectedError = (error) => error.$metadata?.clockSkewCorrected;
    isBrowserNetworkError = (error) => {
      const errorMessages = /* @__PURE__ */ new Set([
        "Failed to fetch",
        "NetworkError when attempting to fetch resource",
        "The Internet connection appears to be offline",
        "Load failed",
        "Network request failed"
      ]);
      const isValid = error && error instanceof TypeError;
      if (!isValid) {
        return false;
      }
      return errorMessages.has(error.message);
    };
    isThrottlingError = (error) => error.$metadata?.httpStatusCode === 429 || THROTTLING_ERROR_CODES.includes(error.name) || error.$retryable?.throttling == true;
    isTransientError = (error, depth = 0) => isRetryableByTrait(error) || isClockSkewCorrectedError(error) || TRANSIENT_ERROR_CODES.includes(error.name) || NODEJS_TIMEOUT_ERROR_CODES2.includes(error?.code || "") || NODEJS_NETWORK_ERROR_CODES.includes(error?.code || "") || TRANSIENT_ERROR_STATUS_CODES.includes(error.$metadata?.httpStatusCode || 0) || isBrowserNetworkError(error) || error.cause !== void 0 && depth <= 10 && isTransientError(error.cause, depth + 1);
    isServerError = (error) => {
      if (error.$metadata?.httpStatusCode !== void 0) {
        const statusCode = error.$metadata.httpStatusCode;
        if (500 <= statusCode && statusCode <= 599 && !isTransientError(error)) {
          return true;
        }
        return false;
      }
      return false;
    };
  }
});

// node_modules/@smithy/util-retry/dist-es/DefaultRateLimiter.js
var DefaultRateLimiter;
var init_DefaultRateLimiter = __esm({
  "node_modules/@smithy/util-retry/dist-es/DefaultRateLimiter.js"() {
    init_dist_es37();
    DefaultRateLimiter = class _DefaultRateLimiter {
      static setTimeoutFn = setTimeout;
      beta;
      minCapacity;
      minFillRate;
      scaleConstant;
      smooth;
      currentCapacity = 0;
      enabled = false;
      lastMaxRate = 0;
      measuredTxRate = 0;
      requestCount = 0;
      fillRate;
      lastThrottleTime;
      lastTimestamp = 0;
      lastTxRateBucket;
      maxCapacity;
      timeWindow = 0;
      constructor(options) {
        this.beta = options?.beta ?? 0.7;
        this.minCapacity = options?.minCapacity ?? 1;
        this.minFillRate = options?.minFillRate ?? 0.5;
        this.scaleConstant = options?.scaleConstant ?? 0.4;
        this.smooth = options?.smooth ?? 0.8;
        const currentTimeInSeconds = this.getCurrentTimeInSeconds();
        this.lastThrottleTime = currentTimeInSeconds;
        this.lastTxRateBucket = Math.floor(this.getCurrentTimeInSeconds());
        this.fillRate = this.minFillRate;
        this.maxCapacity = this.minCapacity;
      }
      getCurrentTimeInSeconds() {
        return Date.now() / 1e3;
      }
      async getSendToken() {
        return this.acquireTokenBucket(1);
      }
      async acquireTokenBucket(amount) {
        if (!this.enabled) {
          return;
        }
        this.refillTokenBucket();
        if (amount > this.currentCapacity) {
          const delay = (amount - this.currentCapacity) / this.fillRate * 1e3;
          await new Promise((resolve) => _DefaultRateLimiter.setTimeoutFn(resolve, delay));
        }
        this.currentCapacity = this.currentCapacity - amount;
      }
      refillTokenBucket() {
        const timestamp = this.getCurrentTimeInSeconds();
        if (!this.lastTimestamp) {
          this.lastTimestamp = timestamp;
          return;
        }
        const fillAmount = (timestamp - this.lastTimestamp) * this.fillRate;
        this.currentCapacity = Math.min(this.maxCapacity, this.currentCapacity + fillAmount);
        this.lastTimestamp = timestamp;
      }
      updateClientSendingRate(response) {
        let calculatedRate;
        this.updateMeasuredRate();
        if (isThrottlingError(response)) {
          const rateToUse = !this.enabled ? this.measuredTxRate : Math.min(this.measuredTxRate, this.fillRate);
          this.lastMaxRate = rateToUse;
          this.calculateTimeWindow();
          this.lastThrottleTime = this.getCurrentTimeInSeconds();
          calculatedRate = this.cubicThrottle(rateToUse);
          this.enableTokenBucket();
        } else {
          this.calculateTimeWindow();
          calculatedRate = this.cubicSuccess(this.getCurrentTimeInSeconds());
        }
        const newRate = Math.min(calculatedRate, 2 * this.measuredTxRate);
        this.updateTokenBucketRate(newRate);
      }
      calculateTimeWindow() {
        this.timeWindow = this.getPrecise(Math.pow(this.lastMaxRate * (1 - this.beta) / this.scaleConstant, 1 / 3));
      }
      cubicThrottle(rateToUse) {
        return this.getPrecise(rateToUse * this.beta);
      }
      cubicSuccess(timestamp) {
        return this.getPrecise(this.scaleConstant * Math.pow(timestamp - this.lastThrottleTime - this.timeWindow, 3) + this.lastMaxRate);
      }
      enableTokenBucket() {
        this.enabled = true;
      }
      updateTokenBucketRate(newRate) {
        this.refillTokenBucket();
        this.fillRate = Math.max(newRate, this.minFillRate);
        this.maxCapacity = Math.max(newRate, this.minCapacity);
        this.currentCapacity = Math.min(this.currentCapacity, this.maxCapacity);
      }
      updateMeasuredRate() {
        const t6 = this.getCurrentTimeInSeconds();
        const timeBucket = Math.floor(t6 * 2) / 2;
        this.requestCount++;
        if (timeBucket > this.lastTxRateBucket) {
          const currentRate = this.requestCount / (timeBucket - this.lastTxRateBucket);
          this.measuredTxRate = this.getPrecise(currentRate * this.smooth + this.measuredTxRate * (1 - this.smooth));
          this.requestCount = 0;
          this.lastTxRateBucket = timeBucket;
        }
      }
      getPrecise(num) {
        return parseFloat(num.toFixed(8));
      }
    };
  }
});

// node_modules/@smithy/util-retry/dist-es/constants.js
var DEFAULT_RETRY_DELAY_BASE, MAXIMUM_RETRY_DELAY, THROTTLING_RETRY_DELAY_BASE, INITIAL_RETRY_TOKENS, RETRY_COST, TIMEOUT_RETRY_COST, NO_RETRY_INCREMENT, INVOCATION_ID_HEADER, REQUEST_HEADER;
var init_constants7 = __esm({
  "node_modules/@smithy/util-retry/dist-es/constants.js"() {
    DEFAULT_RETRY_DELAY_BASE = 100;
    MAXIMUM_RETRY_DELAY = 20 * 1e3;
    THROTTLING_RETRY_DELAY_BASE = 500;
    INITIAL_RETRY_TOKENS = 500;
    RETRY_COST = 5;
    TIMEOUT_RETRY_COST = 10;
    NO_RETRY_INCREMENT = 1;
    INVOCATION_ID_HEADER = "amz-sdk-invocation-id";
    REQUEST_HEADER = "amz-sdk-request";
  }
});

// node_modules/@smithy/util-retry/dist-es/defaultRetryBackoffStrategy.js
var getDefaultRetryBackoffStrategy;
var init_defaultRetryBackoffStrategy = __esm({
  "node_modules/@smithy/util-retry/dist-es/defaultRetryBackoffStrategy.js"() {
    init_constants7();
    getDefaultRetryBackoffStrategy = () => {
      let delayBase = DEFAULT_RETRY_DELAY_BASE;
      const computeNextBackoffDelay = (attempts) => {
        return Math.floor(Math.min(MAXIMUM_RETRY_DELAY, Math.random() * 2 ** attempts * delayBase));
      };
      const setDelayBase = (delay) => {
        delayBase = delay;
      };
      return {
        computeNextBackoffDelay,
        setDelayBase
      };
    };
  }
});

// node_modules/@smithy/util-retry/dist-es/defaultRetryToken.js
var createDefaultRetryToken;
var init_defaultRetryToken = __esm({
  "node_modules/@smithy/util-retry/dist-es/defaultRetryToken.js"() {
    init_constants7();
    createDefaultRetryToken = ({ retryDelay, retryCount, retryCost }) => {
      const getRetryCount = () => retryCount;
      const getRetryDelay = () => Math.min(MAXIMUM_RETRY_DELAY, retryDelay);
      const getRetryCost = () => retryCost;
      return {
        getRetryCount,
        getRetryDelay,
        getRetryCost
      };
    };
  }
});

// node_modules/@smithy/util-retry/dist-es/StandardRetryStrategy.js
var StandardRetryStrategy;
var init_StandardRetryStrategy = __esm({
  "node_modules/@smithy/util-retry/dist-es/StandardRetryStrategy.js"() {
    init_config3();
    init_constants7();
    init_defaultRetryBackoffStrategy();
    init_defaultRetryToken();
    StandardRetryStrategy = class {
      maxAttempts;
      mode = RETRY_MODES.STANDARD;
      capacity = INITIAL_RETRY_TOKENS;
      retryBackoffStrategy = getDefaultRetryBackoffStrategy();
      maxAttemptsProvider;
      constructor(maxAttempts) {
        this.maxAttempts = maxAttempts;
        this.maxAttemptsProvider = typeof maxAttempts === "function" ? maxAttempts : async () => maxAttempts;
      }
      async acquireInitialRetryToken(retryTokenScope) {
        return createDefaultRetryToken({
          retryDelay: DEFAULT_RETRY_DELAY_BASE,
          retryCount: 0
        });
      }
      async refreshRetryTokenForRetry(token, errorInfo) {
        const maxAttempts = await this.getMaxAttempts();
        if (this.shouldRetry(token, errorInfo, maxAttempts)) {
          const errorType = errorInfo.errorType;
          this.retryBackoffStrategy.setDelayBase(errorType === "THROTTLING" ? THROTTLING_RETRY_DELAY_BASE : DEFAULT_RETRY_DELAY_BASE);
          const delayFromErrorType = this.retryBackoffStrategy.computeNextBackoffDelay(token.getRetryCount());
          const retryDelay = errorInfo.retryAfterHint ? Math.max(errorInfo.retryAfterHint.getTime() - Date.now() || 0, delayFromErrorType) : delayFromErrorType;
          const capacityCost = this.getCapacityCost(errorType);
          this.capacity -= capacityCost;
          return createDefaultRetryToken({
            retryDelay,
            retryCount: token.getRetryCount() + 1,
            retryCost: capacityCost
          });
        }
        throw new Error("No retry token available");
      }
      recordSuccess(token) {
        this.capacity = Math.max(INITIAL_RETRY_TOKENS, this.capacity + (token.getRetryCost() ?? NO_RETRY_INCREMENT));
      }
      getCapacity() {
        return this.capacity;
      }
      async getMaxAttempts() {
        try {
          return await this.maxAttemptsProvider();
        } catch (error) {
          console.warn(`Max attempts provider could not resolve. Using default of ${DEFAULT_MAX_ATTEMPTS}`);
          return DEFAULT_MAX_ATTEMPTS;
        }
      }
      shouldRetry(tokenToRenew, errorInfo, maxAttempts) {
        const attempts = tokenToRenew.getRetryCount() + 1;
        return attempts < maxAttempts && this.capacity >= this.getCapacityCost(errorInfo.errorType) && this.isRetryableError(errorInfo.errorType);
      }
      getCapacityCost(errorType) {
        return errorType === "TRANSIENT" ? TIMEOUT_RETRY_COST : RETRY_COST;
      }
      isRetryableError(errorType) {
        return errorType === "THROTTLING" || errorType === "TRANSIENT";
      }
    };
  }
});

// node_modules/@smithy/util-retry/dist-es/AdaptiveRetryStrategy.js
var AdaptiveRetryStrategy;
var init_AdaptiveRetryStrategy = __esm({
  "node_modules/@smithy/util-retry/dist-es/AdaptiveRetryStrategy.js"() {
    init_config3();
    init_DefaultRateLimiter();
    init_StandardRetryStrategy();
    AdaptiveRetryStrategy = class {
      maxAttemptsProvider;
      rateLimiter;
      standardRetryStrategy;
      mode = RETRY_MODES.ADAPTIVE;
      constructor(maxAttemptsProvider, options) {
        this.maxAttemptsProvider = maxAttemptsProvider;
        const { rateLimiter } = options ?? {};
        this.rateLimiter = rateLimiter ?? new DefaultRateLimiter();
        this.standardRetryStrategy = new StandardRetryStrategy(maxAttemptsProvider);
      }
      async acquireInitialRetryToken(retryTokenScope) {
        await this.rateLimiter.getSendToken();
        return this.standardRetryStrategy.acquireInitialRetryToken(retryTokenScope);
      }
      async refreshRetryTokenForRetry(tokenToRenew, errorInfo) {
        this.rateLimiter.updateClientSendingRate(errorInfo);
        return this.standardRetryStrategy.refreshRetryTokenForRetry(tokenToRenew, errorInfo);
      }
      recordSuccess(token) {
        this.rateLimiter.updateClientSendingRate({});
        this.standardRetryStrategy.recordSuccess(token);
      }
    };
  }
});

// node_modules/@smithy/util-retry/dist-es/ConfiguredRetryStrategy.js
var init_ConfiguredRetryStrategy = __esm({
  "node_modules/@smithy/util-retry/dist-es/ConfiguredRetryStrategy.js"() {
  }
});

// node_modules/@smithy/util-retry/dist-es/types.js
var init_types7 = __esm({
  "node_modules/@smithy/util-retry/dist-es/types.js"() {
  }
});

// node_modules/@smithy/util-retry/dist-es/index.js
var init_dist_es38 = __esm({
  "node_modules/@smithy/util-retry/dist-es/index.js"() {
    init_AdaptiveRetryStrategy();
    init_ConfiguredRetryStrategy();
    init_DefaultRateLimiter();
    init_StandardRetryStrategy();
    init_config3();
    init_constants7();
    init_types7();
  }
});

// node_modules/@smithy/middleware-retry/dist-es/delayDecider.js
var init_delayDecider = __esm({
  "node_modules/@smithy/middleware-retry/dist-es/delayDecider.js"() {
  }
});

// node_modules/@smithy/middleware-retry/dist-es/retryDecider.js
var init_retryDecider = __esm({
  "node_modules/@smithy/middleware-retry/dist-es/retryDecider.js"() {
  }
});

// node_modules/@smithy/middleware-retry/dist-es/util.js
var asSdkError;
var init_util3 = __esm({
  "node_modules/@smithy/middleware-retry/dist-es/util.js"() {
    asSdkError = (error) => {
      if (error instanceof Error)
        return error;
      if (error instanceof Object)
        return Object.assign(new Error(), error);
      if (typeof error === "string")
        return new Error(error);
      return new Error(`AWS SDK error wrapper for ${error}`);
    };
  }
});

// node_modules/@smithy/middleware-retry/dist-es/StandardRetryStrategy.js
var init_StandardRetryStrategy2 = __esm({
  "node_modules/@smithy/middleware-retry/dist-es/StandardRetryStrategy.js"() {
  }
});

// node_modules/@smithy/middleware-retry/dist-es/AdaptiveRetryStrategy.js
var init_AdaptiveRetryStrategy2 = __esm({
  "node_modules/@smithy/middleware-retry/dist-es/AdaptiveRetryStrategy.js"() {
  }
});

// node_modules/@smithy/middleware-retry/dist-es/configurations.js
var ENV_MAX_ATTEMPTS, CONFIG_MAX_ATTEMPTS, NODE_MAX_ATTEMPT_CONFIG_OPTIONS, resolveRetryConfig, ENV_RETRY_MODE, CONFIG_RETRY_MODE, NODE_RETRY_MODE_CONFIG_OPTIONS;
var init_configurations2 = __esm({
  "node_modules/@smithy/middleware-retry/dist-es/configurations.js"() {
    init_dist_es6();
    init_dist_es38();
    ENV_MAX_ATTEMPTS = "AWS_MAX_ATTEMPTS";
    CONFIG_MAX_ATTEMPTS = "max_attempts";
    NODE_MAX_ATTEMPT_CONFIG_OPTIONS = {
      environmentVariableSelector: (env2) => {
        const value = env2[ENV_MAX_ATTEMPTS];
        if (!value)
          return void 0;
        const maxAttempt = parseInt(value);
        if (Number.isNaN(maxAttempt)) {
          throw new Error(`Environment variable ${ENV_MAX_ATTEMPTS} mast be a number, got "${value}"`);
        }
        return maxAttempt;
      },
      configFileSelector: (profile) => {
        const value = profile[CONFIG_MAX_ATTEMPTS];
        if (!value)
          return void 0;
        const maxAttempt = parseInt(value);
        if (Number.isNaN(maxAttempt)) {
          throw new Error(`Shared config file entry ${CONFIG_MAX_ATTEMPTS} mast be a number, got "${value}"`);
        }
        return maxAttempt;
      },
      default: DEFAULT_MAX_ATTEMPTS
    };
    resolveRetryConfig = (input) => {
      const { retryStrategy, retryMode: _retryMode, maxAttempts: _maxAttempts } = input;
      const maxAttempts = normalizeProvider(_maxAttempts ?? DEFAULT_MAX_ATTEMPTS);
      return Object.assign(input, {
        maxAttempts,
        retryStrategy: async () => {
          if (retryStrategy) {
            return retryStrategy;
          }
          const retryMode = await normalizeProvider(_retryMode)();
          if (retryMode === RETRY_MODES.ADAPTIVE) {
            return new AdaptiveRetryStrategy(maxAttempts);
          }
          return new StandardRetryStrategy(maxAttempts);
        }
      });
    };
    ENV_RETRY_MODE = "AWS_RETRY_MODE";
    CONFIG_RETRY_MODE = "retry_mode";
    NODE_RETRY_MODE_CONFIG_OPTIONS = {
      environmentVariableSelector: (env2) => env2[ENV_RETRY_MODE],
      configFileSelector: (profile) => profile[CONFIG_RETRY_MODE],
      default: DEFAULT_RETRY_MODE
    };
  }
});

// node_modules/@smithy/middleware-retry/dist-es/omitRetryHeadersMiddleware.js
var init_omitRetryHeadersMiddleware = __esm({
  "node_modules/@smithy/middleware-retry/dist-es/omitRetryHeadersMiddleware.js"() {
  }
});

// node_modules/@smithy/middleware-retry/dist-es/isStreamingPayload/isStreamingPayload.js
import { Readable as Readable3 } from "stream";
var isStreamingPayload;
var init_isStreamingPayload = __esm({
  "node_modules/@smithy/middleware-retry/dist-es/isStreamingPayload/isStreamingPayload.js"() {
    isStreamingPayload = (request2) => request2?.body instanceof Readable3 || typeof ReadableStream !== "undefined" && request2?.body instanceof ReadableStream;
  }
});

// node_modules/@smithy/middleware-retry/dist-es/retryMiddleware.js
var retryMiddleware, isRetryStrategyV2, getRetryErrorInfo, getRetryErrorType, retryMiddlewareOptions, getRetryPlugin, getRetryAfterHint;
var init_retryMiddleware = __esm({
  "node_modules/@smithy/middleware-retry/dist-es/retryMiddleware.js"() {
    init_dist_es2();
    init_dist_es37();
    init_dist_es27();
    init_dist_es38();
    init_dist_es18();
    init_isStreamingPayload();
    init_util3();
    retryMiddleware = (options) => (next, context) => async (args) => {
      let retryStrategy = await options.retryStrategy();
      const maxAttempts = await options.maxAttempts();
      if (isRetryStrategyV2(retryStrategy)) {
        retryStrategy = retryStrategy;
        let retryToken = await retryStrategy.acquireInitialRetryToken(context["partition_id"]);
        let lastError = new Error();
        let attempts = 0;
        let totalRetryDelay = 0;
        const { request: request2 } = args;
        const isRequest = HttpRequest.isInstance(request2);
        if (isRequest) {
          request2.headers[INVOCATION_ID_HEADER] = v4();
        }
        while (true) {
          try {
            if (isRequest) {
              request2.headers[REQUEST_HEADER] = `attempt=${attempts + 1}; max=${maxAttempts}`;
            }
            const { response, output } = await next(args);
            retryStrategy.recordSuccess(retryToken);
            output.$metadata.attempts = attempts + 1;
            output.$metadata.totalRetryDelay = totalRetryDelay;
            return { response, output };
          } catch (e6) {
            const retryErrorInfo = getRetryErrorInfo(e6);
            lastError = asSdkError(e6);
            if (isRequest && isStreamingPayload(request2)) {
              (context.logger instanceof NoOpLogger ? console : context.logger)?.warn("An error was encountered in a non-retryable streaming request.");
              throw lastError;
            }
            try {
              retryToken = await retryStrategy.refreshRetryTokenForRetry(retryToken, retryErrorInfo);
            } catch (refreshError) {
              if (!lastError.$metadata) {
                lastError.$metadata = {};
              }
              lastError.$metadata.attempts = attempts + 1;
              lastError.$metadata.totalRetryDelay = totalRetryDelay;
              throw lastError;
            }
            attempts = retryToken.getRetryCount();
            const delay = retryToken.getRetryDelay();
            totalRetryDelay += delay;
            await new Promise((resolve) => setTimeout(resolve, delay));
          }
        }
      } else {
        retryStrategy = retryStrategy;
        if (retryStrategy?.mode)
          context.userAgent = [...context.userAgent || [], ["cfg/retry-mode", retryStrategy.mode]];
        return retryStrategy.retry(next, args);
      }
    };
    isRetryStrategyV2 = (retryStrategy) => typeof retryStrategy.acquireInitialRetryToken !== "undefined" && typeof retryStrategy.refreshRetryTokenForRetry !== "undefined" && typeof retryStrategy.recordSuccess !== "undefined";
    getRetryErrorInfo = (error) => {
      const errorInfo = {
        error,
        errorType: getRetryErrorType(error)
      };
      const retryAfterHint = getRetryAfterHint(error.$response);
      if (retryAfterHint) {
        errorInfo.retryAfterHint = retryAfterHint;
      }
      return errorInfo;
    };
    getRetryErrorType = (error) => {
      if (isThrottlingError(error))
        return "THROTTLING";
      if (isTransientError(error))
        return "TRANSIENT";
      if (isServerError(error))
        return "SERVER_ERROR";
      return "CLIENT_ERROR";
    };
    retryMiddlewareOptions = {
      name: "retryMiddleware",
      tags: ["RETRY"],
      step: "finalizeRequest",
      priority: "high",
      override: true
    };
    getRetryPlugin = (options) => ({
      applyToStack: (clientStack) => {
        clientStack.add(retryMiddleware(options), retryMiddlewareOptions);
      }
    });
    getRetryAfterHint = (response) => {
      if (!HttpResponse.isInstance(response))
        return;
      const retryAfterHeaderName = Object.keys(response.headers).find((key) => key.toLowerCase() === "retry-after");
      if (!retryAfterHeaderName)
        return;
      const retryAfter = response.headers[retryAfterHeaderName];
      const retryAfterSeconds = Number(retryAfter);
      if (!Number.isNaN(retryAfterSeconds))
        return new Date(retryAfterSeconds * 1e3);
      const retryAfterDate = new Date(retryAfter);
      return retryAfterDate;
    };
  }
});

// node_modules/@smithy/middleware-retry/dist-es/index.js
var init_dist_es39 = __esm({
  "node_modules/@smithy/middleware-retry/dist-es/index.js"() {
    init_AdaptiveRetryStrategy2();
    init_StandardRetryStrategy2();
    init_configurations2();
    init_delayDecider();
    init_omitRetryHeadersMiddleware();
    init_retryDecider();
    init_retryMiddleware();
  }
});

// node_modules/@aws-sdk/credential-provider-env/dist-es/fromEnv.js
var ENV_KEY, ENV_SECRET, ENV_SESSION, ENV_EXPIRATION, ENV_CREDENTIAL_SCOPE, ENV_ACCOUNT_ID, fromEnv2;
var init_fromEnv2 = __esm({
  "node_modules/@aws-sdk/credential-provider-env/dist-es/fromEnv.js"() {
    init_client2();
    init_dist_es24();
    ENV_KEY = "AWS_ACCESS_KEY_ID";
    ENV_SECRET = "AWS_SECRET_ACCESS_KEY";
    ENV_SESSION = "AWS_SESSION_TOKEN";
    ENV_EXPIRATION = "AWS_CREDENTIAL_EXPIRATION";
    ENV_CREDENTIAL_SCOPE = "AWS_CREDENTIAL_SCOPE";
    ENV_ACCOUNT_ID = "AWS_ACCOUNT_ID";
    fromEnv2 = (init) => async () => {
      init?.logger?.debug("@aws-sdk/credential-provider-env - fromEnv");
      const accessKeyId = process.env[ENV_KEY];
      const secretAccessKey = process.env[ENV_SECRET];
      const sessionToken = process.env[ENV_SESSION];
      const expiry = process.env[ENV_EXPIRATION];
      const credentialScope = process.env[ENV_CREDENTIAL_SCOPE];
      const accountId = process.env[ENV_ACCOUNT_ID];
      if (accessKeyId && secretAccessKey) {
        const credentials = {
          accessKeyId,
          secretAccessKey,
          ...sessionToken && { sessionToken },
          ...expiry && { expiration: new Date(expiry) },
          ...credentialScope && { credentialScope },
          ...accountId && { accountId }
        };
        setCredentialFeature(credentials, "CREDENTIALS_ENV_VARS", "g");
        return credentials;
      }
      throw new CredentialsProviderError("Unable to find environment variable credentials.", { logger: init?.logger });
    };
  }
});

// node_modules/@aws-sdk/credential-provider-env/dist-es/index.js
var dist_es_exports = {};
__export(dist_es_exports, {
  ENV_ACCOUNT_ID: () => ENV_ACCOUNT_ID,
  ENV_CREDENTIAL_SCOPE: () => ENV_CREDENTIAL_SCOPE,
  ENV_EXPIRATION: () => ENV_EXPIRATION,
  ENV_KEY: () => ENV_KEY,
  ENV_SECRET: () => ENV_SECRET,
  ENV_SESSION: () => ENV_SESSION,
  fromEnv: () => fromEnv2
});
var init_dist_es40 = __esm({
  "node_modules/@aws-sdk/credential-provider-env/dist-es/index.js"() {
    init_fromEnv2();
  }
});

// node_modules/@smithy/credential-provider-imds/dist-es/remoteProvider/httpRequest.js
import { Buffer as Buffer3 } from "buffer";
import { request } from "http";
function httpRequest(options) {
  return new Promise((resolve, reject) => {
    const req = request({
      method: "GET",
      ...options,
      hostname: options.hostname?.replace(/^\[(.+)\]$/, "$1")
    });
    req.on("error", (err) => {
      reject(Object.assign(new ProviderError("Unable to connect to instance metadata service"), err));
      req.destroy();
    });
    req.on("timeout", () => {
      reject(new ProviderError("TimeoutError from instance metadata service"));
      req.destroy();
    });
    req.on("response", (res) => {
      const { statusCode = 400 } = res;
      if (statusCode < 200 || 300 <= statusCode) {
        reject(Object.assign(new ProviderError("Error response received from instance metadata service"), { statusCode }));
        req.destroy();
      }
      const chunks = [];
      res.on("data", (chunk) => {
        chunks.push(chunk);
      });
      res.on("end", () => {
        resolve(Buffer3.concat(chunks));
        req.destroy();
      });
    });
    req.end();
  });
}
var init_httpRequest2 = __esm({
  "node_modules/@smithy/credential-provider-imds/dist-es/remoteProvider/httpRequest.js"() {
    init_dist_es24();
  }
});

// node_modules/@smithy/credential-provider-imds/dist-es/remoteProvider/ImdsCredentials.js
var isImdsCredentials, fromImdsCredentials;
var init_ImdsCredentials = __esm({
  "node_modules/@smithy/credential-provider-imds/dist-es/remoteProvider/ImdsCredentials.js"() {
    isImdsCredentials = (arg) => Boolean(arg) && typeof arg === "object" && typeof arg.AccessKeyId === "string" && typeof arg.SecretAccessKey === "string" && typeof arg.Token === "string" && typeof arg.Expiration === "string";
    fromImdsCredentials = (creds) => ({
      accessKeyId: creds.AccessKeyId,
      secretAccessKey: creds.SecretAccessKey,
      sessionToken: creds.Token,
      expiration: new Date(creds.Expiration),
      ...creds.AccountId && { accountId: creds.AccountId }
    });
  }
});

// node_modules/@smithy/credential-provider-imds/dist-es/remoteProvider/RemoteProviderInit.js
var DEFAULT_TIMEOUT, DEFAULT_MAX_RETRIES, providerConfigFromInit;
var init_RemoteProviderInit = __esm({
  "node_modules/@smithy/credential-provider-imds/dist-es/remoteProvider/RemoteProviderInit.js"() {
    DEFAULT_TIMEOUT = 1e3;
    DEFAULT_MAX_RETRIES = 0;
    providerConfigFromInit = ({ maxRetries = DEFAULT_MAX_RETRIES, timeout = DEFAULT_TIMEOUT }) => ({ maxRetries, timeout });
  }
});

// node_modules/@smithy/credential-provider-imds/dist-es/remoteProvider/retry.js
var retry;
var init_retry3 = __esm({
  "node_modules/@smithy/credential-provider-imds/dist-es/remoteProvider/retry.js"() {
    retry = (toRetry, maxRetries) => {
      let promise = toRetry();
      for (let i6 = 0; i6 < maxRetries; i6++) {
        promise = promise.catch(toRetry);
      }
      return promise;
    };
  }
});

// node_modules/@smithy/credential-provider-imds/dist-es/fromContainerMetadata.js
import { parse } from "url";
var ENV_CMDS_FULL_URI, ENV_CMDS_RELATIVE_URI, ENV_CMDS_AUTH_TOKEN, fromContainerMetadata, requestFromEcsImds, CMDS_IP, GREENGRASS_HOSTS, GREENGRASS_PROTOCOLS, getCmdsUri;
var init_fromContainerMetadata = __esm({
  "node_modules/@smithy/credential-provider-imds/dist-es/fromContainerMetadata.js"() {
    init_dist_es24();
    init_httpRequest2();
    init_ImdsCredentials();
    init_RemoteProviderInit();
    init_retry3();
    ENV_CMDS_FULL_URI = "AWS_CONTAINER_CREDENTIALS_FULL_URI";
    ENV_CMDS_RELATIVE_URI = "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI";
    ENV_CMDS_AUTH_TOKEN = "AWS_CONTAINER_AUTHORIZATION_TOKEN";
    fromContainerMetadata = (init = {}) => {
      const { timeout, maxRetries } = providerConfigFromInit(init);
      return () => retry(async () => {
        const requestOptions = await getCmdsUri({ logger: init.logger });
        const credsResponse = JSON.parse(await requestFromEcsImds(timeout, requestOptions));
        if (!isImdsCredentials(credsResponse)) {
          throw new CredentialsProviderError("Invalid response received from instance metadata service.", {
            logger: init.logger
          });
        }
        return fromImdsCredentials(credsResponse);
      }, maxRetries);
    };
    requestFromEcsImds = async (timeout, options) => {
      if (process.env[ENV_CMDS_AUTH_TOKEN]) {
        options.headers = {
          ...options.headers,
          Authorization: process.env[ENV_CMDS_AUTH_TOKEN]
        };
      }
      const buffer = await httpRequest({
        ...options,
        timeout
      });
      return buffer.toString();
    };
    CMDS_IP = "169.254.170.2";
    GREENGRASS_HOSTS = {
      localhost: true,
      "127.0.0.1": true
    };
    GREENGRASS_PROTOCOLS = {
      "http:": true,
      "https:": true
    };
    getCmdsUri = async ({ logger: logger2 }) => {
      if (process.env[ENV_CMDS_RELATIVE_URI]) {
        return {
          hostname: CMDS_IP,
          path: process.env[ENV_CMDS_RELATIVE_URI]
        };
      }
      if (process.env[ENV_CMDS_FULL_URI]) {
        const parsed = parse(process.env[ENV_CMDS_FULL_URI]);
        if (!parsed.hostname || !(parsed.hostname in GREENGRASS_HOSTS)) {
          throw new CredentialsProviderError(`${parsed.hostname} is not a valid container metadata service hostname`, {
            tryNextLink: false,
            logger: logger2
          });
        }
        if (!parsed.protocol || !(parsed.protocol in GREENGRASS_PROTOCOLS)) {
          throw new CredentialsProviderError(`${parsed.protocol} is not a valid container metadata service protocol`, {
            tryNextLink: false,
            logger: logger2
          });
        }
        return {
          ...parsed,
          port: parsed.port ? parseInt(parsed.port, 10) : void 0
        };
      }
      throw new CredentialsProviderError(`The container metadata credential provider cannot be used unless the ${ENV_CMDS_RELATIVE_URI} or ${ENV_CMDS_FULL_URI} environment variable is set`, {
        tryNextLink: false,
        logger: logger2
      });
    };
  }
});

// node_modules/@smithy/credential-provider-imds/dist-es/error/InstanceMetadataV1FallbackError.js
var InstanceMetadataV1FallbackError;
var init_InstanceMetadataV1FallbackError = __esm({
  "node_modules/@smithy/credential-provider-imds/dist-es/error/InstanceMetadataV1FallbackError.js"() {
    init_dist_es24();
    InstanceMetadataV1FallbackError = class _InstanceMetadataV1FallbackError extends CredentialsProviderError {
      tryNextLink;
      name = "InstanceMetadataV1FallbackError";
      constructor(message, tryNextLink = true) {
        super(message, tryNextLink);
        this.tryNextLink = tryNextLink;
        Object.setPrototypeOf(this, _InstanceMetadataV1FallbackError.prototype);
      }
    };
  }
});

// node_modules/@smithy/credential-provider-imds/dist-es/config/Endpoint.js
var Endpoint;
var init_Endpoint = __esm({
  "node_modules/@smithy/credential-provider-imds/dist-es/config/Endpoint.js"() {
    (function(Endpoint2) {
      Endpoint2["IPv4"] = "http://169.254.169.254";
      Endpoint2["IPv6"] = "http://[fd00:ec2::254]";
    })(Endpoint || (Endpoint = {}));
  }
});

// node_modules/@smithy/credential-provider-imds/dist-es/config/EndpointConfigOptions.js
var ENV_ENDPOINT_NAME, CONFIG_ENDPOINT_NAME, ENDPOINT_CONFIG_OPTIONS;
var init_EndpointConfigOptions = __esm({
  "node_modules/@smithy/credential-provider-imds/dist-es/config/EndpointConfigOptions.js"() {
    ENV_ENDPOINT_NAME = "AWS_EC2_METADATA_SERVICE_ENDPOINT";
    CONFIG_ENDPOINT_NAME = "ec2_metadata_service_endpoint";
    ENDPOINT_CONFIG_OPTIONS = {
      environmentVariableSelector: (env2) => env2[ENV_ENDPOINT_NAME],
      configFileSelector: (profile) => profile[CONFIG_ENDPOINT_NAME],
      default: void 0
    };
  }
});

// node_modules/@smithy/credential-provider-imds/dist-es/config/EndpointMode.js
var EndpointMode;
var init_EndpointMode = __esm({
  "node_modules/@smithy/credential-provider-imds/dist-es/config/EndpointMode.js"() {
    (function(EndpointMode2) {
      EndpointMode2["IPv4"] = "IPv4";
      EndpointMode2["IPv6"] = "IPv6";
    })(EndpointMode || (EndpointMode = {}));
  }
});

// node_modules/@smithy/credential-provider-imds/dist-es/config/EndpointModeConfigOptions.js
var ENV_ENDPOINT_MODE_NAME, CONFIG_ENDPOINT_MODE_NAME, ENDPOINT_MODE_CONFIG_OPTIONS;
var init_EndpointModeConfigOptions = __esm({
  "node_modules/@smithy/credential-provider-imds/dist-es/config/EndpointModeConfigOptions.js"() {
    init_EndpointMode();
    ENV_ENDPOINT_MODE_NAME = "AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE";
    CONFIG_ENDPOINT_MODE_NAME = "ec2_metadata_service_endpoint_mode";
    ENDPOINT_MODE_CONFIG_OPTIONS = {
      environmentVariableSelector: (env2) => env2[ENV_ENDPOINT_MODE_NAME],
      configFileSelector: (profile) => profile[CONFIG_ENDPOINT_MODE_NAME],
      default: EndpointMode.IPv4
    };
  }
});

// node_modules/@smithy/credential-provider-imds/dist-es/utils/getInstanceMetadataEndpoint.js
var getInstanceMetadataEndpoint, getFromEndpointConfig, getFromEndpointModeConfig;
var init_getInstanceMetadataEndpoint = __esm({
  "node_modules/@smithy/credential-provider-imds/dist-es/utils/getInstanceMetadataEndpoint.js"() {
    init_dist_es35();
    init_dist_es22();
    init_Endpoint();
    init_EndpointConfigOptions();
    init_EndpointMode();
    init_EndpointModeConfigOptions();
    getInstanceMetadataEndpoint = async () => parseUrl(await getFromEndpointConfig() || await getFromEndpointModeConfig());
    getFromEndpointConfig = async () => loadConfig(ENDPOINT_CONFIG_OPTIONS)();
    getFromEndpointModeConfig = async () => {
      const endpointMode = await loadConfig(ENDPOINT_MODE_CONFIG_OPTIONS)();
      switch (endpointMode) {
        case EndpointMode.IPv4:
          return Endpoint.IPv4;
        case EndpointMode.IPv6:
          return Endpoint.IPv6;
        default:
          throw new Error(`Unsupported endpoint mode: ${endpointMode}. Select from ${Object.values(EndpointMode)}`);
      }
    };
  }
});

// node_modules/@smithy/credential-provider-imds/dist-es/utils/getExtendedInstanceMetadataCredentials.js
var STATIC_STABILITY_REFRESH_INTERVAL_SECONDS, STATIC_STABILITY_REFRESH_INTERVAL_JITTER_WINDOW_SECONDS, STATIC_STABILITY_DOC_URL, getExtendedInstanceMetadataCredentials;
var init_getExtendedInstanceMetadataCredentials = __esm({
  "node_modules/@smithy/credential-provider-imds/dist-es/utils/getExtendedInstanceMetadataCredentials.js"() {
    STATIC_STABILITY_REFRESH_INTERVAL_SECONDS = 5 * 60;
    STATIC_STABILITY_REFRESH_INTERVAL_JITTER_WINDOW_SECONDS = 5 * 60;
    STATIC_STABILITY_DOC_URL = "https://docs.aws.amazon.com/sdkref/latest/guide/feature-static-credentials.html";
    getExtendedInstanceMetadataCredentials = (credentials, logger2) => {
      const refreshInterval = STATIC_STABILITY_REFRESH_INTERVAL_SECONDS + Math.floor(Math.random() * STATIC_STABILITY_REFRESH_INTERVAL_JITTER_WINDOW_SECONDS);
      const newExpiration = new Date(Date.now() + refreshInterval * 1e3);
      logger2.warn(`Attempting credential expiration extension due to a credential service availability issue. A refresh of these credentials will be attempted after ${new Date(newExpiration)}.
For more information, please visit: ` + STATIC_STABILITY_DOC_URL);
      const originalExpiration = credentials.originalExpiration ?? credentials.expiration;
      return {
        ...credentials,
        ...originalExpiration ? { originalExpiration } : {},
        expiration: newExpiration
      };
    };
  }
});

// node_modules/@smithy/credential-provider-imds/dist-es/utils/staticStabilityProvider.js
var staticStabilityProvider;
var init_staticStabilityProvider = __esm({
  "node_modules/@smithy/credential-provider-imds/dist-es/utils/staticStabilityProvider.js"() {
    init_getExtendedInstanceMetadataCredentials();
    staticStabilityProvider = (provider, options = {}) => {
      const logger2 = options?.logger || console;
      let pastCredentials;
      return async () => {
        let credentials;
        try {
          credentials = await provider();
          if (credentials.expiration && credentials.expiration.getTime() < Date.now()) {
            credentials = getExtendedInstanceMetadataCredentials(credentials, logger2);
          }
        } catch (e6) {
          if (pastCredentials) {
            logger2.warn("Credential renew failed: ", e6);
            credentials = getExtendedInstanceMetadataCredentials(pastCredentials, logger2);
          } else {
            throw e6;
          }
        }
        pastCredentials = credentials;
        return credentials;
      };
    };
  }
});

// node_modules/@smithy/credential-provider-imds/dist-es/fromInstanceMetadata.js
var IMDS_PATH, IMDS_TOKEN_PATH, AWS_EC2_METADATA_V1_DISABLED, PROFILE_AWS_EC2_METADATA_V1_DISABLED, X_AWS_EC2_METADATA_TOKEN, fromInstanceMetadata, getInstanceMetadataProvider, getMetadataToken, getProfile, getCredentialsFromProfile;
var init_fromInstanceMetadata = __esm({
  "node_modules/@smithy/credential-provider-imds/dist-es/fromInstanceMetadata.js"() {
    init_dist_es35();
    init_dist_es24();
    init_InstanceMetadataV1FallbackError();
    init_httpRequest2();
    init_ImdsCredentials();
    init_RemoteProviderInit();
    init_retry3();
    init_getInstanceMetadataEndpoint();
    init_staticStabilityProvider();
    IMDS_PATH = "/latest/meta-data/iam/security-credentials/";
    IMDS_TOKEN_PATH = "/latest/api/token";
    AWS_EC2_METADATA_V1_DISABLED = "AWS_EC2_METADATA_V1_DISABLED";
    PROFILE_AWS_EC2_METADATA_V1_DISABLED = "ec2_metadata_v1_disabled";
    X_AWS_EC2_METADATA_TOKEN = "x-aws-ec2-metadata-token";
    fromInstanceMetadata = (init = {}) => staticStabilityProvider(getInstanceMetadataProvider(init), { logger: init.logger });
    getInstanceMetadataProvider = (init = {}) => {
      let disableFetchToken = false;
      const { logger: logger2, profile } = init;
      const { timeout, maxRetries } = providerConfigFromInit(init);
      const getCredentials2 = async (maxRetries2, options) => {
        const isImdsV1Fallback = disableFetchToken || options.headers?.[X_AWS_EC2_METADATA_TOKEN] == null;
        if (isImdsV1Fallback) {
          let fallbackBlockedFromProfile = false;
          let fallbackBlockedFromProcessEnv = false;
          const configValue = await loadConfig({
            environmentVariableSelector: (env2) => {
              const envValue = env2[AWS_EC2_METADATA_V1_DISABLED];
              fallbackBlockedFromProcessEnv = !!envValue && envValue !== "false";
              if (envValue === void 0) {
                throw new CredentialsProviderError(`${AWS_EC2_METADATA_V1_DISABLED} not set in env, checking config file next.`, { logger: init.logger });
              }
              return fallbackBlockedFromProcessEnv;
            },
            configFileSelector: (profile2) => {
              const profileValue = profile2[PROFILE_AWS_EC2_METADATA_V1_DISABLED];
              fallbackBlockedFromProfile = !!profileValue && profileValue !== "false";
              return fallbackBlockedFromProfile;
            },
            default: false
          }, {
            profile
          })();
          if (init.ec2MetadataV1Disabled || configValue) {
            const causes = [];
            if (init.ec2MetadataV1Disabled)
              causes.push("credential provider initialization (runtime option ec2MetadataV1Disabled)");
            if (fallbackBlockedFromProfile)
              causes.push(`config file profile (${PROFILE_AWS_EC2_METADATA_V1_DISABLED})`);
            if (fallbackBlockedFromProcessEnv)
              causes.push(`process environment variable (${AWS_EC2_METADATA_V1_DISABLED})`);
            throw new InstanceMetadataV1FallbackError(`AWS EC2 Metadata v1 fallback has been blocked by AWS SDK configuration in the following: [${causes.join(", ")}].`);
          }
        }
        const imdsProfile = (await retry(async () => {
          let profile2;
          try {
            profile2 = await getProfile(options);
          } catch (err) {
            if (err.statusCode === 401) {
              disableFetchToken = false;
            }
            throw err;
          }
          return profile2;
        }, maxRetries2)).trim();
        return retry(async () => {
          let creds;
          try {
            creds = await getCredentialsFromProfile(imdsProfile, options, init);
          } catch (err) {
            if (err.statusCode === 401) {
              disableFetchToken = false;
            }
            throw err;
          }
          return creds;
        }, maxRetries2);
      };
      return async () => {
        const endpoint = await getInstanceMetadataEndpoint();
        if (disableFetchToken) {
          logger2?.debug("AWS SDK Instance Metadata", "using v1 fallback (no token fetch)");
          return getCredentials2(maxRetries, { ...endpoint, timeout });
        } else {
          let token;
          try {
            token = (await getMetadataToken({ ...endpoint, timeout })).toString();
          } catch (error) {
            if (error?.statusCode === 400) {
              throw Object.assign(error, {
                message: "EC2 Metadata token request returned error"
              });
            } else if (error.message === "TimeoutError" || [403, 404, 405].includes(error.statusCode)) {
              disableFetchToken = true;
            }
            logger2?.debug("AWS SDK Instance Metadata", "using v1 fallback (initial)");
            return getCredentials2(maxRetries, { ...endpoint, timeout });
          }
          return getCredentials2(maxRetries, {
            ...endpoint,
            headers: {
              [X_AWS_EC2_METADATA_TOKEN]: token
            },
            timeout
          });
        }
      };
    };
    getMetadataToken = async (options) => httpRequest({
      ...options,
      path: IMDS_TOKEN_PATH,
      method: "PUT",
      headers: {
        "x-aws-ec2-metadata-token-ttl-seconds": "21600"
      }
    });
    getProfile = async (options) => (await httpRequest({ ...options, path: IMDS_PATH })).toString();
    getCredentialsFromProfile = async (profile, options, init) => {
      const credentialsResponse = JSON.parse((await httpRequest({
        ...options,
        path: IMDS_PATH + profile
      })).toString());
      if (!isImdsCredentials(credentialsResponse)) {
        throw new CredentialsProviderError("Invalid response received from instance metadata service.", {
          logger: init.logger
        });
      }
      return fromImdsCredentials(credentialsResponse);
    };
  }
});

// node_modules/@smithy/credential-provider-imds/dist-es/types.js
var init_types8 = __esm({
  "node_modules/@smithy/credential-provider-imds/dist-es/types.js"() {
  }
});

// node_modules/@smithy/credential-provider-imds/dist-es/index.js
var dist_es_exports2 = {};
__export(dist_es_exports2, {
  DEFAULT_MAX_RETRIES: () => DEFAULT_MAX_RETRIES,
  DEFAULT_TIMEOUT: () => DEFAULT_TIMEOUT,
  ENV_CMDS_AUTH_TOKEN: () => ENV_CMDS_AUTH_TOKEN,
  ENV_CMDS_FULL_URI: () => ENV_CMDS_FULL_URI,
  ENV_CMDS_RELATIVE_URI: () => ENV_CMDS_RELATIVE_URI,
  Endpoint: () => Endpoint,
  fromContainerMetadata: () => fromContainerMetadata,
  fromInstanceMetadata: () => fromInstanceMetadata,
  getInstanceMetadataEndpoint: () => getInstanceMetadataEndpoint,
  httpRequest: () => httpRequest,
  providerConfigFromInit: () => providerConfigFromInit
});
var init_dist_es41 = __esm({
  "node_modules/@smithy/credential-provider-imds/dist-es/index.js"() {
    init_fromContainerMetadata();
    init_fromInstanceMetadata();
    init_RemoteProviderInit();
    init_types8();
    init_httpRequest2();
    init_getInstanceMetadataEndpoint();
    init_Endpoint();
  }
});

// node_modules/@aws-sdk/credential-provider-http/dist-es/fromHttp/checkUrl.js
var ECS_CONTAINER_HOST, EKS_CONTAINER_HOST_IPv4, EKS_CONTAINER_HOST_IPv6, checkUrl;
var init_checkUrl = __esm({
  "node_modules/@aws-sdk/credential-provider-http/dist-es/fromHttp/checkUrl.js"() {
    init_dist_es24();
    ECS_CONTAINER_HOST = "169.254.170.2";
    EKS_CONTAINER_HOST_IPv4 = "169.254.170.23";
    EKS_CONTAINER_HOST_IPv6 = "[fd00:ec2::23]";
    checkUrl = (url, logger2) => {
      if (url.protocol === "https:") {
        return;
      }
      if (url.hostname === ECS_CONTAINER_HOST || url.hostname === EKS_CONTAINER_HOST_IPv4 || url.hostname === EKS_CONTAINER_HOST_IPv6) {
        return;
      }
      if (url.hostname.includes("[")) {
        if (url.hostname === "[::1]" || url.hostname === "[0000:0000:0000:0000:0000:0000:0000:0001]") {
          return;
        }
      } else {
        if (url.hostname === "localhost") {
          return;
        }
        const ipComponents = url.hostname.split(".");
        const inRange = (component) => {
          const num = parseInt(component, 10);
          return 0 <= num && num <= 255;
        };
        if (ipComponents[0] === "127" && inRange(ipComponents[1]) && inRange(ipComponents[2]) && inRange(ipComponents[3]) && ipComponents.length === 4) {
          return;
        }
      }
      throw new CredentialsProviderError(`URL not accepted. It must either be HTTPS or match one of the following:
  - loopback CIDR 127.0.0.0/8 or [::1/128]
  - ECS container host 169.254.170.2
  - EKS container host 169.254.170.23 or [fd00:ec2::23]`, { logger: logger2 });
    };
  }
});

// node_modules/@aws-sdk/credential-provider-http/dist-es/fromHttp/requestHelpers.js
function createGetRequest(url) {
  return new HttpRequest({
    protocol: url.protocol,
    hostname: url.hostname,
    port: Number(url.port),
    path: url.pathname,
    query: Array.from(url.searchParams.entries()).reduce((acc, [k6, v7]) => {
      acc[k6] = v7;
      return acc;
    }, {}),
    fragment: url.hash
  });
}
async function getCredentials(response, logger2) {
  const stream = sdkStreamMixin2(response.body);
  const str = await stream.transformToString();
  if (response.statusCode === 200) {
    const parsed = JSON.parse(str);
    if (typeof parsed.AccessKeyId !== "string" || typeof parsed.SecretAccessKey !== "string" || typeof parsed.Token !== "string" || typeof parsed.Expiration !== "string") {
      throw new CredentialsProviderError("HTTP credential provider response not of the required format, an object matching: { AccessKeyId: string, SecretAccessKey: string, Token: string, Expiration: string(rfc3339) }", { logger: logger2 });
    }
    return {
      accessKeyId: parsed.AccessKeyId,
      secretAccessKey: parsed.SecretAccessKey,
      sessionToken: parsed.Token,
      expiration: parseRfc3339DateTime(parsed.Expiration)
    };
  }
  if (response.statusCode >= 400 && response.statusCode < 500) {
    let parsedBody = {};
    try {
      parsedBody = JSON.parse(str);
    } catch (e6) {
    }
    throw Object.assign(new CredentialsProviderError(`Server responded with status: ${response.statusCode}`, { logger: logger2 }), {
      Code: parsedBody.Code,
      Message: parsedBody.Message
    });
  }
  throw new CredentialsProviderError(`Server responded with status: ${response.statusCode}`, { logger: logger2 });
}
var init_requestHelpers = __esm({
  "node_modules/@aws-sdk/credential-provider-http/dist-es/fromHttp/requestHelpers.js"() {
    init_dist_es24();
    init_dist_es2();
    init_dist_es27();
    init_dist_es17();
  }
});

// node_modules/@aws-sdk/credential-provider-http/dist-es/fromHttp/retry-wrapper.js
var retryWrapper;
var init_retry_wrapper = __esm({
  "node_modules/@aws-sdk/credential-provider-http/dist-es/fromHttp/retry-wrapper.js"() {
    retryWrapper = (toRetry, maxRetries, delayMs) => {
      return async () => {
        for (let i6 = 0; i6 < maxRetries; ++i6) {
          try {
            return await toRetry();
          } catch (e6) {
            await new Promise((resolve) => setTimeout(resolve, delayMs));
          }
        }
        return await toRetry();
      };
    };
  }
});

// node_modules/@aws-sdk/credential-provider-http/dist-es/fromHttp/fromHttp.js
import fs from "fs/promises";
var AWS_CONTAINER_CREDENTIALS_RELATIVE_URI, DEFAULT_LINK_LOCAL_HOST, AWS_CONTAINER_CREDENTIALS_FULL_URI, AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE, AWS_CONTAINER_AUTHORIZATION_TOKEN, fromHttp;
var init_fromHttp = __esm({
  "node_modules/@aws-sdk/credential-provider-http/dist-es/fromHttp/fromHttp.js"() {
    init_client2();
    init_dist_es14();
    init_dist_es24();
    init_checkUrl();
    init_requestHelpers();
    init_retry_wrapper();
    AWS_CONTAINER_CREDENTIALS_RELATIVE_URI = "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI";
    DEFAULT_LINK_LOCAL_HOST = "http://169.254.170.2";
    AWS_CONTAINER_CREDENTIALS_FULL_URI = "AWS_CONTAINER_CREDENTIALS_FULL_URI";
    AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE = "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE";
    AWS_CONTAINER_AUTHORIZATION_TOKEN = "AWS_CONTAINER_AUTHORIZATION_TOKEN";
    fromHttp = (options = {}) => {
      options.logger?.debug("@aws-sdk/credential-provider-http - fromHttp");
      let host;
      const relative = options.awsContainerCredentialsRelativeUri ?? process.env[AWS_CONTAINER_CREDENTIALS_RELATIVE_URI];
      const full = options.awsContainerCredentialsFullUri ?? process.env[AWS_CONTAINER_CREDENTIALS_FULL_URI];
      const token = options.awsContainerAuthorizationToken ?? process.env[AWS_CONTAINER_AUTHORIZATION_TOKEN];
      const tokenFile = options.awsContainerAuthorizationTokenFile ?? process.env[AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE];
      const warn = options.logger?.constructor?.name === "NoOpLogger" || !options.logger?.warn ? console.warn : options.logger.warn.bind(options.logger);
      if (relative && full) {
        warn("@aws-sdk/credential-provider-http: you have set both awsContainerCredentialsRelativeUri and awsContainerCredentialsFullUri.");
        warn("awsContainerCredentialsFullUri will take precedence.");
      }
      if (token && tokenFile) {
        warn("@aws-sdk/credential-provider-http: you have set both awsContainerAuthorizationToken and awsContainerAuthorizationTokenFile.");
        warn("awsContainerAuthorizationToken will take precedence.");
      }
      if (full) {
        host = full;
      } else if (relative) {
        host = `${DEFAULT_LINK_LOCAL_HOST}${relative}`;
      } else {
        throw new CredentialsProviderError(`No HTTP credential provider host provided.
Set AWS_CONTAINER_CREDENTIALS_FULL_URI or AWS_CONTAINER_CREDENTIALS_RELATIVE_URI.`, { logger: options.logger });
      }
      const url = new URL(host);
      checkUrl(url, options.logger);
      const requestHandler = NodeHttpHandler.create({
        requestTimeout: options.timeout ?? 1e3,
        connectionTimeout: options.timeout ?? 1e3
      });
      return retryWrapper(async () => {
        const request2 = createGetRequest(url);
        if (token) {
          request2.headers.Authorization = token;
        } else if (tokenFile) {
          request2.headers.Authorization = (await fs.readFile(tokenFile)).toString();
        }
        try {
          const result = await requestHandler.handle(request2);
          return getCredentials(result.response).then((creds) => setCredentialFeature(creds, "CREDENTIALS_HTTP", "z"));
        } catch (e6) {
          throw new CredentialsProviderError(String(e6), { logger: options.logger });
        }
      }, options.maxRetries ?? 3, options.timeout ?? 1e3);
    };
  }
});

// node_modules/@aws-sdk/credential-provider-http/dist-es/index.js
var dist_es_exports3 = {};
__export(dist_es_exports3, {
  fromHttp: () => fromHttp
});
var init_dist_es42 = __esm({
  "node_modules/@aws-sdk/credential-provider-http/dist-es/index.js"() {
    init_fromHttp();
  }
});

// node_modules/@aws-sdk/credential-provider-sso/dist-es/isSsoProfile.js
var isSsoProfile;
var init_isSsoProfile = __esm({
  "node_modules/@aws-sdk/credential-provider-sso/dist-es/isSsoProfile.js"() {
    isSsoProfile = (arg) => arg && (typeof arg.sso_start_url === "string" || typeof arg.sso_account_id === "string" || typeof arg.sso_session === "string" || typeof arg.sso_region === "string" || typeof arg.sso_role_name === "string");
  }
});

// node_modules/@aws-sdk/token-providers/dist-es/fromEnvSigningName.js
var init_fromEnvSigningName = __esm({
  "node_modules/@aws-sdk/token-providers/dist-es/fromEnvSigningName.js"() {
  }
});

// node_modules/@aws-sdk/token-providers/dist-es/constants.js
var EXPIRE_WINDOW_MS, REFRESH_MESSAGE;
var init_constants8 = __esm({
  "node_modules/@aws-sdk/token-providers/dist-es/constants.js"() {
    EXPIRE_WINDOW_MS = 5 * 60 * 1e3;
    REFRESH_MESSAGE = `To refresh this SSO session run 'aws sso login' with the corresponding profile.`;
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/auth/httpAuthSchemeProvider.js
function createAwsAuthSigv4HttpAuthOption2(authParameters) {
  return {
    schemeId: "aws.auth#sigv4",
    signingProperties: {
      name: "sso-oauth",
      region: authParameters.region
    },
    propertiesExtractor: (config, context) => ({
      signingProperties: {
        config,
        context
      }
    })
  };
}
function createSmithyApiNoAuthHttpAuthOption(authParameters) {
  return {
    schemeId: "smithy.api#noAuth"
  };
}
var defaultSSOOIDCHttpAuthSchemeParametersProvider, defaultSSOOIDCHttpAuthSchemeProvider, resolveHttpAuthSchemeConfig2;
var init_httpAuthSchemeProvider = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/auth/httpAuthSchemeProvider.js"() {
    init_dist_es29();
    init_dist_es6();
    defaultSSOOIDCHttpAuthSchemeParametersProvider = async (config, context, input) => {
      return {
        operation: getSmithyContext(context).operation,
        region: await normalizeProvider(config.region)() || (() => {
          throw new Error("expected `region` to be configured for `aws.auth#sigv4`");
        })()
      };
    };
    defaultSSOOIDCHttpAuthSchemeProvider = (authParameters) => {
      const options = [];
      switch (authParameters.operation) {
        case "CreateToken": {
          options.push(createSmithyApiNoAuthHttpAuthOption(authParameters));
          break;
        }
        default: {
          options.push(createAwsAuthSigv4HttpAuthOption2(authParameters));
        }
      }
      return options;
    };
    resolveHttpAuthSchemeConfig2 = (config) => {
      const config_0 = resolveAwsSdkSigV4Config(config);
      return Object.assign(config_0, {
        authSchemePreference: normalizeProvider(config.authSchemePreference ?? [])
      });
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/endpoint/EndpointParameters.js
var resolveClientEndpointParameters2, commonParams2;
var init_EndpointParameters = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/endpoint/EndpointParameters.js"() {
    resolveClientEndpointParameters2 = (options) => {
      return Object.assign(options, {
        useDualstackEndpoint: options.useDualstackEndpoint ?? false,
        useFipsEndpoint: options.useFipsEndpoint ?? false,
        defaultSigningName: "sso-oauth"
      });
    };
    commonParams2 = {
      UseFIPS: { type: "builtInParams", name: "useFipsEndpoint" },
      Endpoint: { type: "builtInParams", name: "endpoint" },
      Region: { type: "builtInParams", name: "region" },
      UseDualStack: { type: "builtInParams", name: "useDualstackEndpoint" }
    };
  }
});

// node_modules/@aws-sdk/nested-clients/package.json
var package_default2;
var init_package = __esm({
  "node_modules/@aws-sdk/nested-clients/package.json"() {
    package_default2 = {
      name: "@aws-sdk/nested-clients",
      version: "3.956.0",
      description: "Nested clients for AWS SDK packages.",
      main: "./dist-cjs/index.js",
      module: "./dist-es/index.js",
      types: "./dist-types/index.d.ts",
      scripts: {
        build: "yarn lint && concurrently 'yarn:build:cjs' 'yarn:build:es' 'yarn:build:types'",
        "build:cjs": "node ../../scripts/compilation/inline nested-clients",
        "build:es": "tsc -p tsconfig.es.json",
        "build:include:deps": "lerna run --scope $npm_package_name --include-dependencies build",
        "build:types": "tsc -p tsconfig.types.json",
        "build:types:downlevel": "downlevel-dts dist-types dist-types/ts3.4",
        clean: "rimraf ./dist-* && rimraf *.tsbuildinfo",
        lint: "node ../../scripts/validation/submodules-linter.js --pkg nested-clients",
        test: "yarn g:vitest run",
        "test:watch": "yarn g:vitest watch"
      },
      engines: {
        node: ">=18.0.0"
      },
      sideEffects: false,
      author: {
        name: "AWS SDK for JavaScript Team",
        url: "https://aws.amazon.com/javascript/"
      },
      license: "Apache-2.0",
      dependencies: {
        "@aws-crypto/sha256-browser": "5.2.0",
        "@aws-crypto/sha256-js": "5.2.0",
        "@aws-sdk/core": "3.956.0",
        "@aws-sdk/middleware-host-header": "3.956.0",
        "@aws-sdk/middleware-logger": "3.956.0",
        "@aws-sdk/middleware-recursion-detection": "3.956.0",
        "@aws-sdk/middleware-user-agent": "3.956.0",
        "@aws-sdk/region-config-resolver": "3.956.0",
        "@aws-sdk/types": "3.956.0",
        "@aws-sdk/util-endpoints": "3.956.0",
        "@aws-sdk/util-user-agent-browser": "3.956.0",
        "@aws-sdk/util-user-agent-node": "3.956.0",
        "@smithy/config-resolver": "^4.4.5",
        "@smithy/core": "^3.20.0",
        "@smithy/fetch-http-handler": "^5.3.8",
        "@smithy/hash-node": "^4.2.7",
        "@smithy/invalid-dependency": "^4.2.7",
        "@smithy/middleware-content-length": "^4.2.7",
        "@smithy/middleware-endpoint": "^4.4.1",
        "@smithy/middleware-retry": "^4.4.17",
        "@smithy/middleware-serde": "^4.2.8",
        "@smithy/middleware-stack": "^4.2.7",
        "@smithy/node-config-provider": "^4.3.7",
        "@smithy/node-http-handler": "^4.4.7",
        "@smithy/protocol-http": "^5.3.7",
        "@smithy/smithy-client": "^4.10.2",
        "@smithy/types": "^4.11.0",
        "@smithy/url-parser": "^4.2.7",
        "@smithy/util-base64": "^4.3.0",
        "@smithy/util-body-length-browser": "^4.2.0",
        "@smithy/util-body-length-node": "^4.2.1",
        "@smithy/util-defaults-mode-browser": "^4.3.16",
        "@smithy/util-defaults-mode-node": "^4.2.19",
        "@smithy/util-endpoints": "^3.2.7",
        "@smithy/util-middleware": "^4.2.7",
        "@smithy/util-retry": "^4.2.7",
        "@smithy/util-utf8": "^4.2.0",
        tslib: "^2.6.2"
      },
      devDependencies: {
        concurrently: "7.0.0",
        "downlevel-dts": "0.10.1",
        rimraf: "3.0.2",
        typescript: "~5.8.3"
      },
      typesVersions: {
        "<4.0": {
          "dist-types/*": [
            "dist-types/ts3.4/*"
          ]
        }
      },
      files: [
        "./signin.d.ts",
        "./signin.js",
        "./sso-oidc.d.ts",
        "./sso-oidc.js",
        "./sts.d.ts",
        "./sts.js",
        "dist-*/**"
      ],
      browser: {
        "./dist-es/submodules/signin/runtimeConfig": "./dist-es/submodules/signin/runtimeConfig.browser",
        "./dist-es/submodules/sso-oidc/runtimeConfig": "./dist-es/submodules/sso-oidc/runtimeConfig.browser",
        "./dist-es/submodules/sts/runtimeConfig": "./dist-es/submodules/sts/runtimeConfig.browser"
      },
      "react-native": {},
      homepage: "https://github.com/aws/aws-sdk-js-v3/tree/main/packages/nested-clients",
      repository: {
        type: "git",
        url: "https://github.com/aws/aws-sdk-js-v3.git",
        directory: "packages/nested-clients"
      },
      exports: {
        "./package.json": "./package.json",
        "./sso-oidc": {
          types: "./dist-types/submodules/sso-oidc/index.d.ts",
          module: "./dist-es/submodules/sso-oidc/index.js",
          node: "./dist-cjs/submodules/sso-oidc/index.js",
          import: "./dist-es/submodules/sso-oidc/index.js",
          require: "./dist-cjs/submodules/sso-oidc/index.js"
        },
        "./sts": {
          types: "./dist-types/submodules/sts/index.d.ts",
          module: "./dist-es/submodules/sts/index.js",
          node: "./dist-cjs/submodules/sts/index.js",
          import: "./dist-es/submodules/sts/index.js",
          require: "./dist-cjs/submodules/sts/index.js"
        },
        "./signin": {
          types: "./dist-types/submodules/signin/index.d.ts",
          module: "./dist-es/submodules/signin/index.js",
          node: "./dist-cjs/submodules/signin/index.js",
          import: "./dist-es/submodules/signin/index.js",
          require: "./dist-cjs/submodules/signin/index.js"
        }
      }
    };
  }
});

// node_modules/@aws-sdk/util-user-agent-node/dist-es/crt-availability.js
var crtAvailability;
var init_crt_availability = __esm({
  "node_modules/@aws-sdk/util-user-agent-node/dist-es/crt-availability.js"() {
    crtAvailability = {
      isCrtAvailable: false
    };
  }
});

// node_modules/@aws-sdk/util-user-agent-node/dist-es/is-crt-available.js
var isCrtAvailable;
var init_is_crt_available = __esm({
  "node_modules/@aws-sdk/util-user-agent-node/dist-es/is-crt-available.js"() {
    init_crt_availability();
    isCrtAvailable = () => {
      if (crtAvailability.isCrtAvailable) {
        return ["md/crt-avail"];
      }
      return null;
    };
  }
});

// node_modules/@aws-sdk/util-user-agent-node/dist-es/defaultUserAgent.js
import { platform, release } from "os";
import { env, versions } from "process";
var createDefaultUserAgentProvider;
var init_defaultUserAgent = __esm({
  "node_modules/@aws-sdk/util-user-agent-node/dist-es/defaultUserAgent.js"() {
    init_is_crt_available();
    createDefaultUserAgentProvider = ({ serviceId, clientVersion }) => {
      return async (config) => {
        const sections = [
          ["aws-sdk-js", clientVersion],
          ["ua", "2.1"],
          [`os/${platform()}`, release()],
          ["lang/js"],
          ["md/nodejs", `${versions.node}`]
        ];
        const crtAvailable = isCrtAvailable();
        if (crtAvailable) {
          sections.push(crtAvailable);
        }
        if (serviceId) {
          sections.push([`api/${serviceId}`, clientVersion]);
        }
        if (env.AWS_EXECUTION_ENV) {
          sections.push([`exec-env/${env.AWS_EXECUTION_ENV}`]);
        }
        const appId = await config?.userAgentAppId?.();
        const resolvedUserAgent = appId ? [...sections, [`app/${appId}`]] : [...sections];
        return resolvedUserAgent;
      };
    };
  }
});

// node_modules/@aws-sdk/util-user-agent-node/dist-es/nodeAppIdConfigOptions.js
var UA_APP_ID_ENV_NAME, UA_APP_ID_INI_NAME, UA_APP_ID_INI_NAME_DEPRECATED, NODE_APP_ID_CONFIG_OPTIONS;
var init_nodeAppIdConfigOptions = __esm({
  "node_modules/@aws-sdk/util-user-agent-node/dist-es/nodeAppIdConfigOptions.js"() {
    init_dist_es30();
    UA_APP_ID_ENV_NAME = "AWS_SDK_UA_APP_ID";
    UA_APP_ID_INI_NAME = "sdk_ua_app_id";
    UA_APP_ID_INI_NAME_DEPRECATED = "sdk-ua-app-id";
    NODE_APP_ID_CONFIG_OPTIONS = {
      environmentVariableSelector: (env2) => env2[UA_APP_ID_ENV_NAME],
      configFileSelector: (profile) => profile[UA_APP_ID_INI_NAME] ?? profile[UA_APP_ID_INI_NAME_DEPRECATED],
      default: DEFAULT_UA_APP_ID
    };
  }
});

// node_modules/@aws-sdk/util-user-agent-node/dist-es/index.js
var init_dist_es43 = __esm({
  "node_modules/@aws-sdk/util-user-agent-node/dist-es/index.js"() {
    init_defaultUserAgent();
    init_nodeAppIdConfigOptions();
  }
});

// node_modules/@smithy/hash-node/dist-es/index.js
import { Buffer as Buffer4 } from "buffer";
import { createHash as createHash2, createHmac } from "crypto";
function castSourceData(toCast, encoding) {
  if (Buffer4.isBuffer(toCast)) {
    return toCast;
  }
  if (typeof toCast === "string") {
    return fromString(toCast, encoding);
  }
  if (ArrayBuffer.isView(toCast)) {
    return fromArrayBuffer(toCast.buffer, toCast.byteOffset, toCast.byteLength);
  }
  return fromArrayBuffer(toCast);
}
var Hash;
var init_dist_es44 = __esm({
  "node_modules/@smithy/hash-node/dist-es/index.js"() {
    init_dist_es9();
    init_dist_es10();
    Hash = class {
      algorithmIdentifier;
      secret;
      hash;
      constructor(algorithmIdentifier, secret) {
        this.algorithmIdentifier = algorithmIdentifier;
        this.secret = secret;
        this.reset();
      }
      update(toHash, encoding) {
        this.hash.update(toUint8Array(castSourceData(toHash, encoding)));
      }
      digest() {
        return Promise.resolve(this.hash.digest());
      }
      reset() {
        this.hash = this.secret ? createHmac(this.algorithmIdentifier, castSourceData(this.secret)) : createHash2(this.algorithmIdentifier);
      }
    };
  }
});

// node_modules/@smithy/util-body-length-node/dist-es/calculateBodyLength.js
import { fstatSync, lstatSync, ReadStream } from "node:fs";
var calculateBodyLength;
var init_calculateBodyLength = __esm({
  "node_modules/@smithy/util-body-length-node/dist-es/calculateBodyLength.js"() {
    calculateBodyLength = (body) => {
      if (!body) {
        return 0;
      }
      if (typeof body === "string") {
        return Buffer.byteLength(body);
      } else if (typeof body.byteLength === "number") {
        return body.byteLength;
      } else if (typeof body.size === "number") {
        return body.size;
      } else if (typeof body.start === "number" && typeof body.end === "number") {
        return body.end + 1 - body.start;
      } else if (body instanceof ReadStream) {
        if (body.path != null) {
          return lstatSync(body.path).size;
        } else if (typeof body.fd === "number") {
          return fstatSync(body.fd).size;
        }
      }
      throw new Error(`Body Length computation failed for ${body}`);
    };
  }
});

// node_modules/@smithy/util-body-length-node/dist-es/index.js
var init_dist_es45 = __esm({
  "node_modules/@smithy/util-body-length-node/dist-es/index.js"() {
    init_calculateBodyLength();
  }
});

// node_modules/@smithy/util-defaults-mode-node/dist-es/constants.js
var AWS_EXECUTION_ENV, AWS_REGION_ENV, AWS_DEFAULT_REGION_ENV, ENV_IMDS_DISABLED2, DEFAULTS_MODE_OPTIONS, IMDS_REGION_PATH;
var init_constants9 = __esm({
  "node_modules/@smithy/util-defaults-mode-node/dist-es/constants.js"() {
    AWS_EXECUTION_ENV = "AWS_EXECUTION_ENV";
    AWS_REGION_ENV = "AWS_REGION";
    AWS_DEFAULT_REGION_ENV = "AWS_DEFAULT_REGION";
    ENV_IMDS_DISABLED2 = "AWS_EC2_METADATA_DISABLED";
    DEFAULTS_MODE_OPTIONS = ["in-region", "cross-region", "mobile", "standard", "legacy"];
    IMDS_REGION_PATH = "/latest/meta-data/placement/region";
  }
});

// node_modules/@smithy/util-defaults-mode-node/dist-es/defaultsModeConfig.js
var AWS_DEFAULTS_MODE_ENV, AWS_DEFAULTS_MODE_CONFIG, NODE_DEFAULTS_MODE_CONFIG_OPTIONS;
var init_defaultsModeConfig = __esm({
  "node_modules/@smithy/util-defaults-mode-node/dist-es/defaultsModeConfig.js"() {
    AWS_DEFAULTS_MODE_ENV = "AWS_DEFAULTS_MODE";
    AWS_DEFAULTS_MODE_CONFIG = "defaults_mode";
    NODE_DEFAULTS_MODE_CONFIG_OPTIONS = {
      environmentVariableSelector: (env2) => {
        return env2[AWS_DEFAULTS_MODE_ENV];
      },
      configFileSelector: (profile) => {
        return profile[AWS_DEFAULTS_MODE_CONFIG];
      },
      default: "legacy"
    };
  }
});

// node_modules/@smithy/util-defaults-mode-node/dist-es/resolveDefaultsModeConfig.js
var resolveDefaultsModeConfig, resolveNodeDefaultsModeAuto, inferPhysicalRegion;
var init_resolveDefaultsModeConfig = __esm({
  "node_modules/@smithy/util-defaults-mode-node/dist-es/resolveDefaultsModeConfig.js"() {
    init_dist_es32();
    init_dist_es35();
    init_dist_es24();
    init_constants9();
    init_defaultsModeConfig();
    resolveDefaultsModeConfig = ({ region = loadConfig(NODE_REGION_CONFIG_OPTIONS), defaultsMode = loadConfig(NODE_DEFAULTS_MODE_CONFIG_OPTIONS) } = {}) => memoize(async () => {
      const mode = typeof defaultsMode === "function" ? await defaultsMode() : defaultsMode;
      switch (mode?.toLowerCase()) {
        case "auto":
          return resolveNodeDefaultsModeAuto(region);
        case "in-region":
        case "cross-region":
        case "mobile":
        case "standard":
        case "legacy":
          return Promise.resolve(mode?.toLocaleLowerCase());
        case void 0:
          return Promise.resolve("legacy");
        default:
          throw new Error(`Invalid parameter for "defaultsMode", expect ${DEFAULTS_MODE_OPTIONS.join(", ")}, got ${mode}`);
      }
    });
    resolveNodeDefaultsModeAuto = async (clientRegion) => {
      if (clientRegion) {
        const resolvedRegion = typeof clientRegion === "function" ? await clientRegion() : clientRegion;
        const inferredRegion = await inferPhysicalRegion();
        if (!inferredRegion) {
          return "standard";
        }
        if (resolvedRegion === inferredRegion) {
          return "in-region";
        } else {
          return "cross-region";
        }
      }
      return "standard";
    };
    inferPhysicalRegion = async () => {
      if (process.env[AWS_EXECUTION_ENV] && (process.env[AWS_REGION_ENV] || process.env[AWS_DEFAULT_REGION_ENV])) {
        return process.env[AWS_REGION_ENV] ?? process.env[AWS_DEFAULT_REGION_ENV];
      }
      if (!process.env[ENV_IMDS_DISABLED2]) {
        try {
          const { getInstanceMetadataEndpoint: getInstanceMetadataEndpoint2, httpRequest: httpRequest2 } = await Promise.resolve().then(() => (init_dist_es41(), dist_es_exports2));
          const endpoint = await getInstanceMetadataEndpoint2();
          return (await httpRequest2({ ...endpoint, path: IMDS_REGION_PATH })).toString();
        } catch (e6) {
        }
      }
    };
  }
});

// node_modules/@smithy/util-defaults-mode-node/dist-es/index.js
var init_dist_es46 = __esm({
  "node_modules/@smithy/util-defaults-mode-node/dist-es/index.js"() {
    init_resolveDefaultsModeConfig();
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/endpoint/ruleset.js
var u, v, w, x, a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, _data, ruleSet;
var init_ruleset = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/endpoint/ruleset.js"() {
    u = "required";
    v = "fn";
    w = "argv";
    x = "ref";
    a = true;
    b = "isSet";
    c = "booleanEquals";
    d = "error";
    e = "endpoint";
    f = "tree";
    g = "PartitionResult";
    h = "getAttr";
    i = { [u]: false, "type": "string" };
    j = { [u]: true, "default": false, "type": "boolean" };
    k = { [x]: "Endpoint" };
    l = { [v]: c, [w]: [{ [x]: "UseFIPS" }, true] };
    m = { [v]: c, [w]: [{ [x]: "UseDualStack" }, true] };
    n = {};
    o = { [v]: h, [w]: [{ [x]: g }, "supportsFIPS"] };
    p = { [x]: g };
    q = { [v]: c, [w]: [true, { [v]: h, [w]: [p, "supportsDualStack"] }] };
    r = [l];
    s = [m];
    t = [{ [x]: "Region" }];
    _data = { version: "1.0", parameters: { Region: i, UseDualStack: j, UseFIPS: j, Endpoint: i }, rules: [{ conditions: [{ [v]: b, [w]: [k] }], rules: [{ conditions: r, error: "Invalid Configuration: FIPS and custom endpoint are not supported", type: d }, { conditions: s, error: "Invalid Configuration: Dualstack and custom endpoint are not supported", type: d }, { endpoint: { url: k, properties: n, headers: n }, type: e }], type: f }, { conditions: [{ [v]: b, [w]: t }], rules: [{ conditions: [{ [v]: "aws.partition", [w]: t, assign: g }], rules: [{ conditions: [l, m], rules: [{ conditions: [{ [v]: c, [w]: [a, o] }, q], rules: [{ endpoint: { url: "https://oidc-fips.{Region}.{PartitionResult#dualStackDnsSuffix}", properties: n, headers: n }, type: e }], type: f }, { error: "FIPS and DualStack are enabled, but this partition does not support one or both", type: d }], type: f }, { conditions: r, rules: [{ conditions: [{ [v]: c, [w]: [o, a] }], rules: [{ conditions: [{ [v]: "stringEquals", [w]: [{ [v]: h, [w]: [p, "name"] }, "aws-us-gov"] }], endpoint: { url: "https://oidc.{Region}.amazonaws.com", properties: n, headers: n }, type: e }, { endpoint: { url: "https://oidc-fips.{Region}.{PartitionResult#dnsSuffix}", properties: n, headers: n }, type: e }], type: f }, { error: "FIPS is enabled but this partition does not support FIPS", type: d }], type: f }, { conditions: s, rules: [{ conditions: [q], rules: [{ endpoint: { url: "https://oidc.{Region}.{PartitionResult#dualStackDnsSuffix}", properties: n, headers: n }, type: e }], type: f }, { error: "DualStack is enabled but this partition does not support DualStack", type: d }], type: f }, { endpoint: { url: "https://oidc.{Region}.{PartitionResult#dnsSuffix}", properties: n, headers: n }, type: e }], type: f }], type: f }, { error: "Invalid Configuration: Missing Region", type: d }] };
    ruleSet = _data;
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/endpoint/endpointResolver.js
var cache, defaultEndpointResolver;
var init_endpointResolver = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/endpoint/endpointResolver.js"() {
    init_dist_es23();
    init_dist_es20();
    init_ruleset();
    cache = new EndpointCache({
      size: 50,
      params: ["Endpoint", "Region", "UseDualStack", "UseFIPS"]
    });
    defaultEndpointResolver = (endpointParams, context = {}) => {
      return cache.get(endpointParams, () => resolveEndpoint(ruleSet, {
        endpointParams,
        logger: context.logger
      }));
    };
    customEndpointFunctions.aws = awsEndpointFunctions;
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/runtimeConfig.shared.js
var getRuntimeConfig;
var init_runtimeConfig_shared = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/runtimeConfig.shared.js"() {
    init_dist_es29();
    init_protocols2();
    init_dist_es19();
    init_dist_es27();
    init_dist_es22();
    init_dist_es11();
    init_dist_es10();
    init_httpAuthSchemeProvider();
    init_endpointResolver();
    getRuntimeConfig = (config) => {
      return {
        apiVersion: "2019-06-10",
        base64Decoder: config?.base64Decoder ?? fromBase64,
        base64Encoder: config?.base64Encoder ?? toBase64,
        disableHostPrefix: config?.disableHostPrefix ?? false,
        endpointProvider: config?.endpointProvider ?? defaultEndpointResolver,
        extensions: config?.extensions ?? [],
        httpAuthSchemeProvider: config?.httpAuthSchemeProvider ?? defaultSSOOIDCHttpAuthSchemeProvider,
        httpAuthSchemes: config?.httpAuthSchemes ?? [
          {
            schemeId: "aws.auth#sigv4",
            identityProvider: (ipc) => ipc.getIdentityProvider("aws.auth#sigv4"),
            signer: new AwsSdkSigV4Signer()
          },
          {
            schemeId: "smithy.api#noAuth",
            identityProvider: (ipc) => ipc.getIdentityProvider("smithy.api#noAuth") || (async () => ({})),
            signer: new NoAuthSigner()
          }
        ],
        logger: config?.logger ?? new NoOpLogger(),
        protocol: config?.protocol ?? AwsRestJsonProtocol,
        protocolSettings: config?.protocolSettings ?? {
          defaultNamespace: "com.amazonaws.ssooidc",
          version: "2019-06-10",
          serviceTarget: "AWSSSOOIDCService"
        },
        serviceId: config?.serviceId ?? "SSO OIDC",
        urlParser: config?.urlParser ?? parseUrl,
        utf8Decoder: config?.utf8Decoder ?? fromUtf8,
        utf8Encoder: config?.utf8Encoder ?? toUtf8
      };
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/runtimeConfig.js
var getRuntimeConfig2;
var init_runtimeConfig = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/runtimeConfig.js"() {
    init_package();
    init_dist_es29();
    init_dist_es43();
    init_dist_es32();
    init_dist_es44();
    init_dist_es39();
    init_dist_es35();
    init_dist_es14();
    init_dist_es27();
    init_dist_es45();
    init_dist_es46();
    init_dist_es38();
    init_runtimeConfig_shared();
    getRuntimeConfig2 = (config) => {
      emitWarningIfUnsupportedVersion2(process.version);
      const defaultsMode = resolveDefaultsModeConfig(config);
      const defaultConfigProvider = () => defaultsMode().then(loadConfigsForDefaultMode);
      const clientSharedValues = getRuntimeConfig(config);
      emitWarningIfUnsupportedVersion(process.version);
      const loaderConfig = {
        profile: config?.profile,
        logger: clientSharedValues.logger
      };
      return {
        ...clientSharedValues,
        ...config,
        runtime: "node",
        defaultsMode,
        authSchemePreference: config?.authSchemePreference ?? loadConfig(NODE_AUTH_SCHEME_PREFERENCE_OPTIONS, loaderConfig),
        bodyLengthChecker: config?.bodyLengthChecker ?? calculateBodyLength,
        defaultUserAgentProvider: config?.defaultUserAgentProvider ?? createDefaultUserAgentProvider({ serviceId: clientSharedValues.serviceId, clientVersion: package_default2.version }),
        maxAttempts: config?.maxAttempts ?? loadConfig(NODE_MAX_ATTEMPT_CONFIG_OPTIONS, config),
        region: config?.region ?? loadConfig(NODE_REGION_CONFIG_OPTIONS, { ...NODE_REGION_CONFIG_FILE_OPTIONS, ...loaderConfig }),
        requestHandler: NodeHttpHandler.create(config?.requestHandler ?? defaultConfigProvider),
        retryMode: config?.retryMode ?? loadConfig({
          ...NODE_RETRY_MODE_CONFIG_OPTIONS,
          default: async () => (await defaultConfigProvider()).retryMode || DEFAULT_RETRY_MODE
        }, config),
        sha256: config?.sha256 ?? Hash.bind(null, "sha256"),
        streamCollector: config?.streamCollector ?? streamCollector,
        useDualstackEndpoint: config?.useDualstackEndpoint ?? loadConfig(NODE_USE_DUALSTACK_ENDPOINT_CONFIG_OPTIONS, loaderConfig),
        useFipsEndpoint: config?.useFipsEndpoint ?? loadConfig(NODE_USE_FIPS_ENDPOINT_CONFIG_OPTIONS, loaderConfig),
        userAgentAppId: config?.userAgentAppId ?? loadConfig(NODE_APP_ID_CONFIG_OPTIONS, loaderConfig)
      };
    };
  }
});

// node_modules/@aws-sdk/region-config-resolver/dist-es/extensions/index.js
var getAwsRegionExtensionConfiguration, resolveAwsRegionExtensionConfiguration;
var init_extensions4 = __esm({
  "node_modules/@aws-sdk/region-config-resolver/dist-es/extensions/index.js"() {
    getAwsRegionExtensionConfiguration = (runtimeConfig) => {
      return {
        setRegion(region) {
          runtimeConfig.region = region;
        },
        region() {
          return runtimeConfig.region;
        }
      };
    };
    resolveAwsRegionExtensionConfiguration = (awsRegionExtensionConfiguration) => {
      return {
        region: awsRegionExtensionConfiguration.region()
      };
    };
  }
});

// node_modules/@aws-sdk/region-config-resolver/dist-es/regionConfig/awsRegionConfig.js
var init_awsRegionConfig = __esm({
  "node_modules/@aws-sdk/region-config-resolver/dist-es/regionConfig/awsRegionConfig.js"() {
  }
});

// node_modules/@aws-sdk/region-config-resolver/dist-es/regionConfig/stsRegionDefaultResolver.js
function stsRegionDefaultResolver(loaderConfig = {}) {
  return loadConfig({
    ...NODE_REGION_CONFIG_OPTIONS,
    async default() {
      if (!warning.silence) {
        console.warn("@aws-sdk - WARN - default STS region of us-east-1 used. See @aws-sdk/credential-providers README and set a region explicitly.");
      }
      return "us-east-1";
    }
  }, { ...NODE_REGION_CONFIG_FILE_OPTIONS, ...loaderConfig });
}
var warning;
var init_stsRegionDefaultResolver = __esm({
  "node_modules/@aws-sdk/region-config-resolver/dist-es/regionConfig/stsRegionDefaultResolver.js"() {
    init_dist_es32();
    init_dist_es35();
    warning = {
      silence: false
    };
  }
});

// node_modules/@aws-sdk/region-config-resolver/dist-es/index.js
var init_dist_es47 = __esm({
  "node_modules/@aws-sdk/region-config-resolver/dist-es/index.js"() {
    init_extensions4();
    init_awsRegionConfig();
    init_stsRegionDefaultResolver();
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/auth/httpAuthExtensionConfiguration.js
var getHttpAuthExtensionConfiguration, resolveHttpAuthRuntimeConfig;
var init_httpAuthExtensionConfiguration = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/auth/httpAuthExtensionConfiguration.js"() {
    getHttpAuthExtensionConfiguration = (runtimeConfig) => {
      const _httpAuthSchemes = runtimeConfig.httpAuthSchemes;
      let _httpAuthSchemeProvider = runtimeConfig.httpAuthSchemeProvider;
      let _credentials = runtimeConfig.credentials;
      return {
        setHttpAuthScheme(httpAuthScheme) {
          const index = _httpAuthSchemes.findIndex((scheme) => scheme.schemeId === httpAuthScheme.schemeId);
          if (index === -1) {
            _httpAuthSchemes.push(httpAuthScheme);
          } else {
            _httpAuthSchemes.splice(index, 1, httpAuthScheme);
          }
        },
        httpAuthSchemes() {
          return _httpAuthSchemes;
        },
        setHttpAuthSchemeProvider(httpAuthSchemeProvider) {
          _httpAuthSchemeProvider = httpAuthSchemeProvider;
        },
        httpAuthSchemeProvider() {
          return _httpAuthSchemeProvider;
        },
        setCredentials(credentials) {
          _credentials = credentials;
        },
        credentials() {
          return _credentials;
        }
      };
    };
    resolveHttpAuthRuntimeConfig = (config) => {
      return {
        httpAuthSchemes: config.httpAuthSchemes(),
        httpAuthSchemeProvider: config.httpAuthSchemeProvider(),
        credentials: config.credentials()
      };
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/runtimeExtensions.js
var resolveRuntimeExtensions;
var init_runtimeExtensions = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/runtimeExtensions.js"() {
    init_dist_es47();
    init_dist_es2();
    init_dist_es27();
    init_httpAuthExtensionConfiguration();
    resolveRuntimeExtensions = (runtimeConfig, extensions) => {
      const extensionConfiguration = Object.assign(getAwsRegionExtensionConfiguration(runtimeConfig), getDefaultExtensionConfiguration(runtimeConfig), getHttpHandlerExtensionConfiguration(runtimeConfig), getHttpAuthExtensionConfiguration(runtimeConfig));
      extensions.forEach((extension) => extension.configure(extensionConfiguration));
      return Object.assign(runtimeConfig, resolveAwsRegionExtensionConfiguration(extensionConfiguration), resolveDefaultRuntimeConfig(extensionConfiguration), resolveHttpHandlerRuntimeConfig(extensionConfiguration), resolveHttpAuthRuntimeConfig(extensionConfiguration));
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/SSOOIDCClient.js
var SSOOIDCClient;
var init_SSOOIDCClient = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/SSOOIDCClient.js"() {
    init_dist_es3();
    init_dist_es4();
    init_dist_es5();
    init_dist_es30();
    init_dist_es32();
    init_dist_es19();
    init_schema2();
    init_dist_es33();
    init_dist_es36();
    init_dist_es39();
    init_dist_es27();
    init_httpAuthSchemeProvider();
    init_EndpointParameters();
    init_runtimeConfig();
    init_runtimeExtensions();
    SSOOIDCClient = class extends Client {
      config;
      constructor(...[configuration]) {
        const _config_0 = getRuntimeConfig2(configuration || {});
        super(_config_0);
        this.initConfig = _config_0;
        const _config_1 = resolveClientEndpointParameters2(_config_0);
        const _config_2 = resolveUserAgentConfig(_config_1);
        const _config_3 = resolveRetryConfig(_config_2);
        const _config_4 = resolveRegionConfig(_config_3);
        const _config_5 = resolveHostHeaderConfig(_config_4);
        const _config_6 = resolveEndpointConfig(_config_5);
        const _config_7 = resolveHttpAuthSchemeConfig2(_config_6);
        const _config_8 = resolveRuntimeExtensions(_config_7, configuration?.extensions || []);
        this.config = _config_8;
        this.middlewareStack.use(getSchemaSerdePlugin(this.config));
        this.middlewareStack.use(getUserAgentPlugin(this.config));
        this.middlewareStack.use(getRetryPlugin(this.config));
        this.middlewareStack.use(getContentLengthPlugin(this.config));
        this.middlewareStack.use(getHostHeaderPlugin(this.config));
        this.middlewareStack.use(getLoggerPlugin(this.config));
        this.middlewareStack.use(getRecursionDetectionPlugin(this.config));
        this.middlewareStack.use(getHttpAuthSchemeEndpointRuleSetPlugin(this.config, {
          httpAuthSchemeParametersProvider: defaultSSOOIDCHttpAuthSchemeParametersProvider,
          identityProviderConfigProvider: async (config) => new DefaultIdentityProviderConfig({
            "aws.auth#sigv4": config.credentials
          })
        }));
        this.middlewareStack.use(getHttpSigningPlugin(this.config));
      }
      destroy() {
        super.destroy();
      }
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/models/SSOOIDCServiceException.js
var SSOOIDCServiceException;
var init_SSOOIDCServiceException = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/models/SSOOIDCServiceException.js"() {
    init_dist_es27();
    SSOOIDCServiceException = class _SSOOIDCServiceException extends ServiceException {
      constructor(options) {
        super(options);
        Object.setPrototypeOf(this, _SSOOIDCServiceException.prototype);
      }
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/models/errors.js
var AccessDeniedException, AuthorizationPendingException, ExpiredTokenException, InternalServerException, InvalidClientException, InvalidGrantException, InvalidRequestException, InvalidScopeException, SlowDownException, UnauthorizedClientException, UnsupportedGrantTypeException;
var init_errors = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/models/errors.js"() {
    init_SSOOIDCServiceException();
    AccessDeniedException = class _AccessDeniedException extends SSOOIDCServiceException {
      name = "AccessDeniedException";
      $fault = "client";
      error;
      reason;
      error_description;
      constructor(opts) {
        super({
          name: "AccessDeniedException",
          $fault: "client",
          ...opts
        });
        Object.setPrototypeOf(this, _AccessDeniedException.prototype);
        this.error = opts.error;
        this.reason = opts.reason;
        this.error_description = opts.error_description;
      }
    };
    AuthorizationPendingException = class _AuthorizationPendingException extends SSOOIDCServiceException {
      name = "AuthorizationPendingException";
      $fault = "client";
      error;
      error_description;
      constructor(opts) {
        super({
          name: "AuthorizationPendingException",
          $fault: "client",
          ...opts
        });
        Object.setPrototypeOf(this, _AuthorizationPendingException.prototype);
        this.error = opts.error;
        this.error_description = opts.error_description;
      }
    };
    ExpiredTokenException = class _ExpiredTokenException extends SSOOIDCServiceException {
      name = "ExpiredTokenException";
      $fault = "client";
      error;
      error_description;
      constructor(opts) {
        super({
          name: "ExpiredTokenException",
          $fault: "client",
          ...opts
        });
        Object.setPrototypeOf(this, _ExpiredTokenException.prototype);
        this.error = opts.error;
        this.error_description = opts.error_description;
      }
    };
    InternalServerException = class _InternalServerException extends SSOOIDCServiceException {
      name = "InternalServerException";
      $fault = "server";
      error;
      error_description;
      constructor(opts) {
        super({
          name: "InternalServerException",
          $fault: "server",
          ...opts
        });
        Object.setPrototypeOf(this, _InternalServerException.prototype);
        this.error = opts.error;
        this.error_description = opts.error_description;
      }
    };
    InvalidClientException = class _InvalidClientException extends SSOOIDCServiceException {
      name = "InvalidClientException";
      $fault = "client";
      error;
      error_description;
      constructor(opts) {
        super({
          name: "InvalidClientException",
          $fault: "client",
          ...opts
        });
        Object.setPrototypeOf(this, _InvalidClientException.prototype);
        this.error = opts.error;
        this.error_description = opts.error_description;
      }
    };
    InvalidGrantException = class _InvalidGrantException extends SSOOIDCServiceException {
      name = "InvalidGrantException";
      $fault = "client";
      error;
      error_description;
      constructor(opts) {
        super({
          name: "InvalidGrantException",
          $fault: "client",
          ...opts
        });
        Object.setPrototypeOf(this, _InvalidGrantException.prototype);
        this.error = opts.error;
        this.error_description = opts.error_description;
      }
    };
    InvalidRequestException = class _InvalidRequestException extends SSOOIDCServiceException {
      name = "InvalidRequestException";
      $fault = "client";
      error;
      reason;
      error_description;
      constructor(opts) {
        super({
          name: "InvalidRequestException",
          $fault: "client",
          ...opts
        });
        Object.setPrototypeOf(this, _InvalidRequestException.prototype);
        this.error = opts.error;
        this.reason = opts.reason;
        this.error_description = opts.error_description;
      }
    };
    InvalidScopeException = class _InvalidScopeException extends SSOOIDCServiceException {
      name = "InvalidScopeException";
      $fault = "client";
      error;
      error_description;
      constructor(opts) {
        super({
          name: "InvalidScopeException",
          $fault: "client",
          ...opts
        });
        Object.setPrototypeOf(this, _InvalidScopeException.prototype);
        this.error = opts.error;
        this.error_description = opts.error_description;
      }
    };
    SlowDownException = class _SlowDownException extends SSOOIDCServiceException {
      name = "SlowDownException";
      $fault = "client";
      error;
      error_description;
      constructor(opts) {
        super({
          name: "SlowDownException",
          $fault: "client",
          ...opts
        });
        Object.setPrototypeOf(this, _SlowDownException.prototype);
        this.error = opts.error;
        this.error_description = opts.error_description;
      }
    };
    UnauthorizedClientException = class _UnauthorizedClientException extends SSOOIDCServiceException {
      name = "UnauthorizedClientException";
      $fault = "client";
      error;
      error_description;
      constructor(opts) {
        super({
          name: "UnauthorizedClientException",
          $fault: "client",
          ...opts
        });
        Object.setPrototypeOf(this, _UnauthorizedClientException.prototype);
        this.error = opts.error;
        this.error_description = opts.error_description;
      }
    };
    UnsupportedGrantTypeException = class _UnsupportedGrantTypeException extends SSOOIDCServiceException {
      name = "UnsupportedGrantTypeException";
      $fault = "client";
      error;
      error_description;
      constructor(opts) {
        super({
          name: "UnsupportedGrantTypeException",
          $fault: "client",
          ...opts
        });
        Object.setPrototypeOf(this, _UnsupportedGrantTypeException.prototype);
        this.error = opts.error;
        this.error_description = opts.error_description;
      }
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/schemas/schemas_0.js
var _ADE, _APE, _AT, _CS, _CT, _CTR, _CTRr, _CV, _ETE, _ICE, _IGE, _IRE, _ISE, _ISEn, _IT, _RT, _SDE, _UCE, _UGTE, _aT, _c, _cI, _cS, _cV, _co, _dC, _e, _eI, _ed, _gT, _h, _hE, _iT, _r, _rT, _rU, _s, _se, _sm, _tT, n0, AccessToken, ClientSecret, CodeVerifier, IdToken, RefreshToken, AccessDeniedException$, AuthorizationPendingException$, CreateTokenRequest$, CreateTokenResponse$, ExpiredTokenException$, InternalServerException$, InvalidClientException$, InvalidGrantException$, InvalidRequestException$, InvalidScopeException$, SlowDownException$, UnauthorizedClientException$, UnsupportedGrantTypeException$, SSOOIDCServiceException$, Scopes, CreateToken$;
var init_schemas_0 = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/schemas/schemas_0.js"() {
    init_schema2();
    init_errors();
    init_SSOOIDCServiceException();
    _ADE = "AccessDeniedException";
    _APE = "AuthorizationPendingException";
    _AT = "AccessToken";
    _CS = "ClientSecret";
    _CT = "CreateToken";
    _CTR = "CreateTokenRequest";
    _CTRr = "CreateTokenResponse";
    _CV = "CodeVerifier";
    _ETE = "ExpiredTokenException";
    _ICE = "InvalidClientException";
    _IGE = "InvalidGrantException";
    _IRE = "InvalidRequestException";
    _ISE = "InternalServerException";
    _ISEn = "InvalidScopeException";
    _IT = "IdToken";
    _RT = "RefreshToken";
    _SDE = "SlowDownException";
    _UCE = "UnauthorizedClientException";
    _UGTE = "UnsupportedGrantTypeException";
    _aT = "accessToken";
    _c = "client";
    _cI = "clientId";
    _cS = "clientSecret";
    _cV = "codeVerifier";
    _co = "code";
    _dC = "deviceCode";
    _e = "error";
    _eI = "expiresIn";
    _ed = "error_description";
    _gT = "grantType";
    _h = "http";
    _hE = "httpError";
    _iT = "idToken";
    _r = "reason";
    _rT = "refreshToken";
    _rU = "redirectUri";
    _s = "scope";
    _se = "server";
    _sm = "smithy.ts.sdk.synthetic.com.amazonaws.ssooidc";
    _tT = "tokenType";
    n0 = "com.amazonaws.ssooidc";
    AccessToken = [0, n0, _AT, 8, 0];
    ClientSecret = [0, n0, _CS, 8, 0];
    CodeVerifier = [0, n0, _CV, 8, 0];
    IdToken = [0, n0, _IT, 8, 0];
    RefreshToken = [0, n0, _RT, 8, 0];
    AccessDeniedException$ = [
      -3,
      n0,
      _ADE,
      { [_e]: _c, [_hE]: 400 },
      [_e, _r, _ed],
      [0, 0, 0]
    ];
    TypeRegistry.for(n0).registerError(AccessDeniedException$, AccessDeniedException);
    AuthorizationPendingException$ = [
      -3,
      n0,
      _APE,
      { [_e]: _c, [_hE]: 400 },
      [_e, _ed],
      [0, 0]
    ];
    TypeRegistry.for(n0).registerError(AuthorizationPendingException$, AuthorizationPendingException);
    CreateTokenRequest$ = [
      3,
      n0,
      _CTR,
      0,
      [_cI, _cS, _gT, _dC, _co, _rT, _s, _rU, _cV],
      [0, [() => ClientSecret, 0], 0, 0, 0, [() => RefreshToken, 0], 64 | 0, 0, [() => CodeVerifier, 0]]
    ];
    CreateTokenResponse$ = [
      3,
      n0,
      _CTRr,
      0,
      [_aT, _tT, _eI, _rT, _iT],
      [[() => AccessToken, 0], 0, 1, [() => RefreshToken, 0], [() => IdToken, 0]]
    ];
    ExpiredTokenException$ = [-3, n0, _ETE, { [_e]: _c, [_hE]: 400 }, [_e, _ed], [0, 0]];
    TypeRegistry.for(n0).registerError(ExpiredTokenException$, ExpiredTokenException);
    InternalServerException$ = [-3, n0, _ISE, { [_e]: _se, [_hE]: 500 }, [_e, _ed], [0, 0]];
    TypeRegistry.for(n0).registerError(InternalServerException$, InternalServerException);
    InvalidClientException$ = [-3, n0, _ICE, { [_e]: _c, [_hE]: 401 }, [_e, _ed], [0, 0]];
    TypeRegistry.for(n0).registerError(InvalidClientException$, InvalidClientException);
    InvalidGrantException$ = [-3, n0, _IGE, { [_e]: _c, [_hE]: 400 }, [_e, _ed], [0, 0]];
    TypeRegistry.for(n0).registerError(InvalidGrantException$, InvalidGrantException);
    InvalidRequestException$ = [
      -3,
      n0,
      _IRE,
      { [_e]: _c, [_hE]: 400 },
      [_e, _r, _ed],
      [0, 0, 0]
    ];
    TypeRegistry.for(n0).registerError(InvalidRequestException$, InvalidRequestException);
    InvalidScopeException$ = [-3, n0, _ISEn, { [_e]: _c, [_hE]: 400 }, [_e, _ed], [0, 0]];
    TypeRegistry.for(n0).registerError(InvalidScopeException$, InvalidScopeException);
    SlowDownException$ = [-3, n0, _SDE, { [_e]: _c, [_hE]: 400 }, [_e, _ed], [0, 0]];
    TypeRegistry.for(n0).registerError(SlowDownException$, SlowDownException);
    UnauthorizedClientException$ = [
      -3,
      n0,
      _UCE,
      { [_e]: _c, [_hE]: 400 },
      [_e, _ed],
      [0, 0]
    ];
    TypeRegistry.for(n0).registerError(UnauthorizedClientException$, UnauthorizedClientException);
    UnsupportedGrantTypeException$ = [
      -3,
      n0,
      _UGTE,
      { [_e]: _c, [_hE]: 400 },
      [_e, _ed],
      [0, 0]
    ];
    TypeRegistry.for(n0).registerError(UnsupportedGrantTypeException$, UnsupportedGrantTypeException);
    SSOOIDCServiceException$ = [-3, _sm, "SSOOIDCServiceException", 0, [], []];
    TypeRegistry.for(_sm).registerError(SSOOIDCServiceException$, SSOOIDCServiceException);
    Scopes = 64 | 0;
    CreateToken$ = [
      9,
      n0,
      _CT,
      { [_h]: ["POST", "/token", 200] },
      () => CreateTokenRequest$,
      () => CreateTokenResponse$
    ];
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/commands/CreateTokenCommand.js
var CreateTokenCommand;
var init_CreateTokenCommand = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/commands/CreateTokenCommand.js"() {
    init_dist_es36();
    init_dist_es27();
    init_EndpointParameters();
    init_schemas_0();
    CreateTokenCommand = class extends Command.classBuilder().ep(commonParams2).m(function(Command2, cs, config, o6) {
      return [getEndpointPlugin(config, Command2.getEndpointParameterInstructions())];
    }).s("AWSSSOOIDCService", "CreateToken", {}).n("SSOOIDCClient", "CreateTokenCommand").sc(CreateToken$).build() {
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/SSOOIDC.js
var commands, SSOOIDC;
var init_SSOOIDC = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/SSOOIDC.js"() {
    init_dist_es27();
    init_CreateTokenCommand();
    init_SSOOIDCClient();
    commands = {
      CreateTokenCommand
    };
    SSOOIDC = class extends SSOOIDCClient {
    };
    createAggregatedClient(commands, SSOOIDC);
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/commands/index.js
var init_commands = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/commands/index.js"() {
    init_CreateTokenCommand();
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/models/enums.js
var AccessDeniedExceptionReason, InvalidRequestExceptionReason;
var init_enums = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/models/enums.js"() {
    AccessDeniedExceptionReason = {
      KMS_ACCESS_DENIED: "KMS_AccessDeniedException"
    };
    InvalidRequestExceptionReason = {
      KMS_DISABLED_KEY: "KMS_DisabledException",
      KMS_INVALID_KEY_USAGE: "KMS_InvalidKeyUsageException",
      KMS_INVALID_STATE: "KMS_InvalidStateException",
      KMS_KEY_NOT_FOUND: "KMS_NotFoundException"
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/models/models_0.js
var init_models_0 = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/models/models_0.js"() {
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/index.js
var sso_oidc_exports = {};
__export(sso_oidc_exports, {
  $Command: () => Command,
  AccessDeniedException: () => AccessDeniedException,
  AccessDeniedException$: () => AccessDeniedException$,
  AccessDeniedExceptionReason: () => AccessDeniedExceptionReason,
  AuthorizationPendingException: () => AuthorizationPendingException,
  AuthorizationPendingException$: () => AuthorizationPendingException$,
  CreateToken$: () => CreateToken$,
  CreateTokenCommand: () => CreateTokenCommand,
  CreateTokenRequest$: () => CreateTokenRequest$,
  CreateTokenResponse$: () => CreateTokenResponse$,
  ExpiredTokenException: () => ExpiredTokenException,
  ExpiredTokenException$: () => ExpiredTokenException$,
  InternalServerException: () => InternalServerException,
  InternalServerException$: () => InternalServerException$,
  InvalidClientException: () => InvalidClientException,
  InvalidClientException$: () => InvalidClientException$,
  InvalidGrantException: () => InvalidGrantException,
  InvalidGrantException$: () => InvalidGrantException$,
  InvalidRequestException: () => InvalidRequestException,
  InvalidRequestException$: () => InvalidRequestException$,
  InvalidRequestExceptionReason: () => InvalidRequestExceptionReason,
  InvalidScopeException: () => InvalidScopeException,
  InvalidScopeException$: () => InvalidScopeException$,
  SSOOIDC: () => SSOOIDC,
  SSOOIDCClient: () => SSOOIDCClient,
  SSOOIDCServiceException: () => SSOOIDCServiceException,
  SSOOIDCServiceException$: () => SSOOIDCServiceException$,
  SlowDownException: () => SlowDownException,
  SlowDownException$: () => SlowDownException$,
  UnauthorizedClientException: () => UnauthorizedClientException,
  UnauthorizedClientException$: () => UnauthorizedClientException$,
  UnsupportedGrantTypeException: () => UnsupportedGrantTypeException,
  UnsupportedGrantTypeException$: () => UnsupportedGrantTypeException$,
  __Client: () => Client
});
var init_sso_oidc = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/index.js"() {
    init_SSOOIDCClient();
    init_SSOOIDC();
    init_commands();
    init_schemas_0();
    init_enums();
    init_errors();
    init_models_0();
    init_SSOOIDCServiceException();
  }
});

// node_modules/@aws-sdk/token-providers/dist-es/getSsoOidcClient.js
var getSsoOidcClient;
var init_getSsoOidcClient = __esm({
  "node_modules/@aws-sdk/token-providers/dist-es/getSsoOidcClient.js"() {
    getSsoOidcClient = async (ssoRegion, init = {}, callerClientConfig) => {
      const { SSOOIDCClient: SSOOIDCClient2 } = await Promise.resolve().then(() => (init_sso_oidc(), sso_oidc_exports));
      const coalesce = (prop) => init.clientConfig?.[prop] ?? init.parentClientConfig?.[prop] ?? callerClientConfig?.[prop];
      const ssoOidcClient = new SSOOIDCClient2(Object.assign({}, init.clientConfig ?? {}, {
        region: ssoRegion ?? init.clientConfig?.region,
        logger: coalesce("logger"),
        userAgentAppId: coalesce("userAgentAppId")
      }));
      return ssoOidcClient;
    };
  }
});

// node_modules/@aws-sdk/token-providers/dist-es/getNewSsoOidcToken.js
var getNewSsoOidcToken;
var init_getNewSsoOidcToken = __esm({
  "node_modules/@aws-sdk/token-providers/dist-es/getNewSsoOidcToken.js"() {
    init_getSsoOidcClient();
    getNewSsoOidcToken = async (ssoToken, ssoRegion, init = {}, callerClientConfig) => {
      const { CreateTokenCommand: CreateTokenCommand2 } = await Promise.resolve().then(() => (init_sso_oidc(), sso_oidc_exports));
      const ssoOidcClient = await getSsoOidcClient(ssoRegion, init, callerClientConfig);
      return ssoOidcClient.send(new CreateTokenCommand2({
        clientId: ssoToken.clientId,
        clientSecret: ssoToken.clientSecret,
        refreshToken: ssoToken.refreshToken,
        grantType: "refresh_token"
      }));
    };
  }
});

// node_modules/@aws-sdk/token-providers/dist-es/validateTokenExpiry.js
var validateTokenExpiry;
var init_validateTokenExpiry = __esm({
  "node_modules/@aws-sdk/token-providers/dist-es/validateTokenExpiry.js"() {
    init_dist_es24();
    init_constants8();
    validateTokenExpiry = (token) => {
      if (token.expiration && token.expiration.getTime() < Date.now()) {
        throw new TokenProviderError(`Token is expired. ${REFRESH_MESSAGE}`, false);
      }
    };
  }
});

// node_modules/@aws-sdk/token-providers/dist-es/validateTokenKey.js
var validateTokenKey;
var init_validateTokenKey = __esm({
  "node_modules/@aws-sdk/token-providers/dist-es/validateTokenKey.js"() {
    init_dist_es24();
    init_constants8();
    validateTokenKey = (key, value, forRefresh = false) => {
      if (typeof value === "undefined") {
        throw new TokenProviderError(`Value not present for '${key}' in SSO Token${forRefresh ? ". Cannot refresh" : ""}. ${REFRESH_MESSAGE}`, false);
      }
    };
  }
});

// node_modules/@aws-sdk/token-providers/dist-es/writeSSOTokenToFile.js
import { promises as fsPromises } from "fs";
var writeFile, writeSSOTokenToFile;
var init_writeSSOTokenToFile = __esm({
  "node_modules/@aws-sdk/token-providers/dist-es/writeSSOTokenToFile.js"() {
    init_dist_es34();
    ({ writeFile } = fsPromises);
    writeSSOTokenToFile = (id, ssoToken) => {
      const tokenFilepath = getSSOTokenFilepath(id);
      const tokenString = JSON.stringify(ssoToken, null, 2);
      return writeFile(tokenFilepath, tokenString);
    };
  }
});

// node_modules/@aws-sdk/token-providers/dist-es/fromSso.js
var lastRefreshAttemptTime, fromSso;
var init_fromSso = __esm({
  "node_modules/@aws-sdk/token-providers/dist-es/fromSso.js"() {
    init_dist_es24();
    init_dist_es34();
    init_constants8();
    init_getNewSsoOidcToken();
    init_validateTokenExpiry();
    init_validateTokenKey();
    init_writeSSOTokenToFile();
    lastRefreshAttemptTime = /* @__PURE__ */ new Date(0);
    fromSso = (init = {}) => async ({ callerClientConfig } = {}) => {
      init.logger?.debug("@aws-sdk/token-providers - fromSso");
      const profiles = await parseKnownFiles(init);
      const profileName = getProfileName({
        profile: init.profile ?? callerClientConfig?.profile
      });
      const profile = profiles[profileName];
      if (!profile) {
        throw new TokenProviderError(`Profile '${profileName}' could not be found in shared credentials file.`, false);
      } else if (!profile["sso_session"]) {
        throw new TokenProviderError(`Profile '${profileName}' is missing required property 'sso_session'.`);
      }
      const ssoSessionName = profile["sso_session"];
      const ssoSessions = await loadSsoSessionData(init);
      const ssoSession = ssoSessions[ssoSessionName];
      if (!ssoSession) {
        throw new TokenProviderError(`Sso session '${ssoSessionName}' could not be found in shared credentials file.`, false);
      }
      for (const ssoSessionRequiredKey of ["sso_start_url", "sso_region"]) {
        if (!ssoSession[ssoSessionRequiredKey]) {
          throw new TokenProviderError(`Sso session '${ssoSessionName}' is missing required property '${ssoSessionRequiredKey}'.`, false);
        }
      }
      const ssoStartUrl = ssoSession["sso_start_url"];
      const ssoRegion = ssoSession["sso_region"];
      let ssoToken;
      try {
        ssoToken = await getSSOTokenFromFile(ssoSessionName);
      } catch (e6) {
        throw new TokenProviderError(`The SSO session token associated with profile=${profileName} was not found or is invalid. ${REFRESH_MESSAGE}`, false);
      }
      validateTokenKey("accessToken", ssoToken.accessToken);
      validateTokenKey("expiresAt", ssoToken.expiresAt);
      const { accessToken, expiresAt } = ssoToken;
      const existingToken = { token: accessToken, expiration: new Date(expiresAt) };
      if (existingToken.expiration.getTime() - Date.now() > EXPIRE_WINDOW_MS) {
        return existingToken;
      }
      if (Date.now() - lastRefreshAttemptTime.getTime() < 30 * 1e3) {
        validateTokenExpiry(existingToken);
        return existingToken;
      }
      validateTokenKey("clientId", ssoToken.clientId, true);
      validateTokenKey("clientSecret", ssoToken.clientSecret, true);
      validateTokenKey("refreshToken", ssoToken.refreshToken, true);
      try {
        lastRefreshAttemptTime.setTime(Date.now());
        const newSsoOidcToken = await getNewSsoOidcToken(ssoToken, ssoRegion, init, callerClientConfig);
        validateTokenKey("accessToken", newSsoOidcToken.accessToken);
        validateTokenKey("expiresIn", newSsoOidcToken.expiresIn);
        const newTokenExpiration = new Date(Date.now() + newSsoOidcToken.expiresIn * 1e3);
        try {
          await writeSSOTokenToFile(ssoSessionName, {
            ...ssoToken,
            accessToken: newSsoOidcToken.accessToken,
            expiresAt: newTokenExpiration.toISOString(),
            refreshToken: newSsoOidcToken.refreshToken
          });
        } catch (error) {
        }
        return {
          token: newSsoOidcToken.accessToken,
          expiration: newTokenExpiration
        };
      } catch (error) {
        validateTokenExpiry(existingToken);
        return existingToken;
      }
    };
  }
});

// node_modules/@aws-sdk/token-providers/dist-es/fromStatic.js
var init_fromStatic3 = __esm({
  "node_modules/@aws-sdk/token-providers/dist-es/fromStatic.js"() {
  }
});

// node_modules/@aws-sdk/token-providers/dist-es/nodeProvider.js
var init_nodeProvider = __esm({
  "node_modules/@aws-sdk/token-providers/dist-es/nodeProvider.js"() {
  }
});

// node_modules/@aws-sdk/token-providers/dist-es/index.js
var init_dist_es48 = __esm({
  "node_modules/@aws-sdk/token-providers/dist-es/index.js"() {
    init_fromEnvSigningName();
    init_fromSso();
    init_fromStatic3();
    init_nodeProvider();
  }
});

// node_modules/@aws-sdk/client-sso/dist-es/auth/httpAuthSchemeProvider.js
function createAwsAuthSigv4HttpAuthOption3(authParameters) {
  return {
    schemeId: "aws.auth#sigv4",
    signingProperties: {
      name: "awsssoportal",
      region: authParameters.region
    },
    propertiesExtractor: (config, context) => ({
      signingProperties: {
        config,
        context
      }
    })
  };
}
function createSmithyApiNoAuthHttpAuthOption2(authParameters) {
  return {
    schemeId: "smithy.api#noAuth"
  };
}
var defaultSSOHttpAuthSchemeParametersProvider, defaultSSOHttpAuthSchemeProvider, resolveHttpAuthSchemeConfig3;
var init_httpAuthSchemeProvider2 = __esm({
  "node_modules/@aws-sdk/client-sso/dist-es/auth/httpAuthSchemeProvider.js"() {
    init_dist_es29();
    init_dist_es6();
    defaultSSOHttpAuthSchemeParametersProvider = async (config, context, input) => {
      return {
        operation: getSmithyContext(context).operation,
        region: await normalizeProvider(config.region)() || (() => {
          throw new Error("expected `region` to be configured for `aws.auth#sigv4`");
        })()
      };
    };
    defaultSSOHttpAuthSchemeProvider = (authParameters) => {
      const options = [];
      switch (authParameters.operation) {
        case "GetRoleCredentials": {
          options.push(createSmithyApiNoAuthHttpAuthOption2(authParameters));
          break;
        }
        case "ListAccountRoles": {
          options.push(createSmithyApiNoAuthHttpAuthOption2(authParameters));
          break;
        }
        case "ListAccounts": {
          options.push(createSmithyApiNoAuthHttpAuthOption2(authParameters));
          break;
        }
        case "Logout": {
          options.push(createSmithyApiNoAuthHttpAuthOption2(authParameters));
          break;
        }
        default: {
          options.push(createAwsAuthSigv4HttpAuthOption3(authParameters));
        }
      }
      return options;
    };
    resolveHttpAuthSchemeConfig3 = (config) => {
      const config_0 = resolveAwsSdkSigV4Config(config);
      return Object.assign(config_0, {
        authSchemePreference: normalizeProvider(config.authSchemePreference ?? [])
      });
    };
  }
});

// node_modules/@aws-sdk/client-sso/dist-es/endpoint/EndpointParameters.js
var resolveClientEndpointParameters3, commonParams3;
var init_EndpointParameters2 = __esm({
  "node_modules/@aws-sdk/client-sso/dist-es/endpoint/EndpointParameters.js"() {
    resolveClientEndpointParameters3 = (options) => {
      return Object.assign(options, {
        useDualstackEndpoint: options.useDualstackEndpoint ?? false,
        useFipsEndpoint: options.useFipsEndpoint ?? false,
        defaultSigningName: "awsssoportal"
      });
    };
    commonParams3 = {
      UseFIPS: { type: "builtInParams", name: "useFipsEndpoint" },
      Endpoint: { type: "builtInParams", name: "endpoint" },
      Region: { type: "builtInParams", name: "region" },
      UseDualStack: { type: "builtInParams", name: "useDualstackEndpoint" }
    };
  }
});

// node_modules/@aws-sdk/client-sso/package.json
var package_default3;
var init_package2 = __esm({
  "node_modules/@aws-sdk/client-sso/package.json"() {
    package_default3 = {
      name: "@aws-sdk/client-sso",
      description: "AWS SDK for JavaScript Sso Client for Node.js, Browser and React Native",
      version: "3.956.0",
      scripts: {
        build: "concurrently 'yarn:build:types' 'yarn:build:es' && yarn build:cjs",
        "build:cjs": "node ../../scripts/compilation/inline client-sso",
        "build:es": "tsc -p tsconfig.es.json",
        "build:include:deps": "lerna run --scope $npm_package_name --include-dependencies build",
        "build:types": "tsc -p tsconfig.types.json",
        "build:types:downlevel": "downlevel-dts dist-types dist-types/ts3.4",
        clean: "rimraf ./dist-* && rimraf *.tsbuildinfo",
        "extract:docs": "api-extractor run --local",
        "generate:client": "node ../../scripts/generate-clients/single-service --solo sso",
        "test:index": "tsc --noEmit ./test/index-types.ts && node ./test/index-objects.spec.mjs"
      },
      main: "./dist-cjs/index.js",
      types: "./dist-types/index.d.ts",
      module: "./dist-es/index.js",
      sideEffects: false,
      dependencies: {
        "@aws-crypto/sha256-browser": "5.2.0",
        "@aws-crypto/sha256-js": "5.2.0",
        "@aws-sdk/core": "3.956.0",
        "@aws-sdk/middleware-host-header": "3.956.0",
        "@aws-sdk/middleware-logger": "3.956.0",
        "@aws-sdk/middleware-recursion-detection": "3.956.0",
        "@aws-sdk/middleware-user-agent": "3.956.0",
        "@aws-sdk/region-config-resolver": "3.956.0",
        "@aws-sdk/types": "3.956.0",
        "@aws-sdk/util-endpoints": "3.956.0",
        "@aws-sdk/util-user-agent-browser": "3.956.0",
        "@aws-sdk/util-user-agent-node": "3.956.0",
        "@smithy/config-resolver": "^4.4.5",
        "@smithy/core": "^3.20.0",
        "@smithy/fetch-http-handler": "^5.3.8",
        "@smithy/hash-node": "^4.2.7",
        "@smithy/invalid-dependency": "^4.2.7",
        "@smithy/middleware-content-length": "^4.2.7",
        "@smithy/middleware-endpoint": "^4.4.1",
        "@smithy/middleware-retry": "^4.4.17",
        "@smithy/middleware-serde": "^4.2.8",
        "@smithy/middleware-stack": "^4.2.7",
        "@smithy/node-config-provider": "^4.3.7",
        "@smithy/node-http-handler": "^4.4.7",
        "@smithy/protocol-http": "^5.3.7",
        "@smithy/smithy-client": "^4.10.2",
        "@smithy/types": "^4.11.0",
        "@smithy/url-parser": "^4.2.7",
        "@smithy/util-base64": "^4.3.0",
        "@smithy/util-body-length-browser": "^4.2.0",
        "@smithy/util-body-length-node": "^4.2.1",
        "@smithy/util-defaults-mode-browser": "^4.3.16",
        "@smithy/util-defaults-mode-node": "^4.2.19",
        "@smithy/util-endpoints": "^3.2.7",
        "@smithy/util-middleware": "^4.2.7",
        "@smithy/util-retry": "^4.2.7",
        "@smithy/util-utf8": "^4.2.0",
        tslib: "^2.6.2"
      },
      devDependencies: {
        "@tsconfig/node18": "18.2.4",
        "@types/node": "^18.19.69",
        concurrently: "7.0.0",
        "downlevel-dts": "0.10.1",
        rimraf: "3.0.2",
        typescript: "~5.8.3"
      },
      engines: {
        node: ">=18.0.0"
      },
      typesVersions: {
        "<4.0": {
          "dist-types/*": [
            "dist-types/ts3.4/*"
          ]
        }
      },
      files: [
        "dist-*/**"
      ],
      author: {
        name: "AWS SDK for JavaScript Team",
        url: "https://aws.amazon.com/javascript/"
      },
      license: "Apache-2.0",
      browser: {
        "./dist-es/runtimeConfig": "./dist-es/runtimeConfig.browser"
      },
      "react-native": {
        "./dist-es/runtimeConfig": "./dist-es/runtimeConfig.native"
      },
      homepage: "https://github.com/aws/aws-sdk-js-v3/tree/main/clients/client-sso",
      repository: {
        type: "git",
        url: "https://github.com/aws/aws-sdk-js-v3.git",
        directory: "clients/client-sso"
      }
    };
  }
});

// node_modules/@aws-sdk/client-sso/dist-es/endpoint/ruleset.js
var u2, v2, w2, x2, a2, b2, c2, d2, e2, f2, g2, h2, i2, j2, k2, l2, m2, n2, o2, p2, q2, r2, s2, t2, _data2, ruleSet2;
var init_ruleset2 = __esm({
  "node_modules/@aws-sdk/client-sso/dist-es/endpoint/ruleset.js"() {
    u2 = "required";
    v2 = "fn";
    w2 = "argv";
    x2 = "ref";
    a2 = true;
    b2 = "isSet";
    c2 = "booleanEquals";
    d2 = "error";
    e2 = "endpoint";
    f2 = "tree";
    g2 = "PartitionResult";
    h2 = "getAttr";
    i2 = { [u2]: false, "type": "string" };
    j2 = { [u2]: true, "default": false, "type": "boolean" };
    k2 = { [x2]: "Endpoint" };
    l2 = { [v2]: c2, [w2]: [{ [x2]: "UseFIPS" }, true] };
    m2 = { [v2]: c2, [w2]: [{ [x2]: "UseDualStack" }, true] };
    n2 = {};
    o2 = { [v2]: h2, [w2]: [{ [x2]: g2 }, "supportsFIPS"] };
    p2 = { [x2]: g2 };
    q2 = { [v2]: c2, [w2]: [true, { [v2]: h2, [w2]: [p2, "supportsDualStack"] }] };
    r2 = [l2];
    s2 = [m2];
    t2 = [{ [x2]: "Region" }];
    _data2 = { version: "1.0", parameters: { Region: i2, UseDualStack: j2, UseFIPS: j2, Endpoint: i2 }, rules: [{ conditions: [{ [v2]: b2, [w2]: [k2] }], rules: [{ conditions: r2, error: "Invalid Configuration: FIPS and custom endpoint are not supported", type: d2 }, { conditions: s2, error: "Invalid Configuration: Dualstack and custom endpoint are not supported", type: d2 }, { endpoint: { url: k2, properties: n2, headers: n2 }, type: e2 }], type: f2 }, { conditions: [{ [v2]: b2, [w2]: t2 }], rules: [{ conditions: [{ [v2]: "aws.partition", [w2]: t2, assign: g2 }], rules: [{ conditions: [l2, m2], rules: [{ conditions: [{ [v2]: c2, [w2]: [a2, o2] }, q2], rules: [{ endpoint: { url: "https://portal.sso-fips.{Region}.{PartitionResult#dualStackDnsSuffix}", properties: n2, headers: n2 }, type: e2 }], type: f2 }, { error: "FIPS and DualStack are enabled, but this partition does not support one or both", type: d2 }], type: f2 }, { conditions: r2, rules: [{ conditions: [{ [v2]: c2, [w2]: [o2, a2] }], rules: [{ conditions: [{ [v2]: "stringEquals", [w2]: [{ [v2]: h2, [w2]: [p2, "name"] }, "aws-us-gov"] }], endpoint: { url: "https://portal.sso.{Region}.amazonaws.com", properties: n2, headers: n2 }, type: e2 }, { endpoint: { url: "https://portal.sso-fips.{Region}.{PartitionResult#dnsSuffix}", properties: n2, headers: n2 }, type: e2 }], type: f2 }, { error: "FIPS is enabled but this partition does not support FIPS", type: d2 }], type: f2 }, { conditions: s2, rules: [{ conditions: [q2], rules: [{ endpoint: { url: "https://portal.sso.{Region}.{PartitionResult#dualStackDnsSuffix}", properties: n2, headers: n2 }, type: e2 }], type: f2 }, { error: "DualStack is enabled but this partition does not support DualStack", type: d2 }], type: f2 }, { endpoint: { url: "https://portal.sso.{Region}.{PartitionResult#dnsSuffix}", properties: n2, headers: n2 }, type: e2 }], type: f2 }], type: f2 }, { error: "Invalid Configuration: Missing Region", type: d2 }] };
    ruleSet2 = _data2;
  }
});

// node_modules/@aws-sdk/client-sso/dist-es/endpoint/endpointResolver.js
var cache2, defaultEndpointResolver2;
var init_endpointResolver2 = __esm({
  "node_modules/@aws-sdk/client-sso/dist-es/endpoint/endpointResolver.js"() {
    init_dist_es23();
    init_dist_es20();
    init_ruleset2();
    cache2 = new EndpointCache({
      size: 50,
      params: ["Endpoint", "Region", "UseDualStack", "UseFIPS"]
    });
    defaultEndpointResolver2 = (endpointParams, context = {}) => {
      return cache2.get(endpointParams, () => resolveEndpoint(ruleSet2, {
        endpointParams,
        logger: context.logger
      }));
    };
    customEndpointFunctions.aws = awsEndpointFunctions;
  }
});

// node_modules/@aws-sdk/client-sso/dist-es/runtimeConfig.shared.js
var getRuntimeConfig3;
var init_runtimeConfig_shared2 = __esm({
  "node_modules/@aws-sdk/client-sso/dist-es/runtimeConfig.shared.js"() {
    init_dist_es29();
    init_protocols2();
    init_dist_es19();
    init_dist_es27();
    init_dist_es22();
    init_dist_es11();
    init_dist_es10();
    init_httpAuthSchemeProvider2();
    init_endpointResolver2();
    getRuntimeConfig3 = (config) => {
      return {
        apiVersion: "2019-06-10",
        base64Decoder: config?.base64Decoder ?? fromBase64,
        base64Encoder: config?.base64Encoder ?? toBase64,
        disableHostPrefix: config?.disableHostPrefix ?? false,
        endpointProvider: config?.endpointProvider ?? defaultEndpointResolver2,
        extensions: config?.extensions ?? [],
        httpAuthSchemeProvider: config?.httpAuthSchemeProvider ?? defaultSSOHttpAuthSchemeProvider,
        httpAuthSchemes: config?.httpAuthSchemes ?? [
          {
            schemeId: "aws.auth#sigv4",
            identityProvider: (ipc) => ipc.getIdentityProvider("aws.auth#sigv4"),
            signer: new AwsSdkSigV4Signer()
          },
          {
            schemeId: "smithy.api#noAuth",
            identityProvider: (ipc) => ipc.getIdentityProvider("smithy.api#noAuth") || (async () => ({})),
            signer: new NoAuthSigner()
          }
        ],
        logger: config?.logger ?? new NoOpLogger(),
        protocol: config?.protocol ?? AwsRestJsonProtocol,
        protocolSettings: config?.protocolSettings ?? {
          defaultNamespace: "com.amazonaws.sso",
          version: "2019-06-10",
          serviceTarget: "SWBPortalService"
        },
        serviceId: config?.serviceId ?? "SSO",
        urlParser: config?.urlParser ?? parseUrl,
        utf8Decoder: config?.utf8Decoder ?? fromUtf8,
        utf8Encoder: config?.utf8Encoder ?? toUtf8
      };
    };
  }
});

// node_modules/@aws-sdk/client-sso/dist-es/runtimeConfig.js
var getRuntimeConfig4;
var init_runtimeConfig2 = __esm({
  "node_modules/@aws-sdk/client-sso/dist-es/runtimeConfig.js"() {
    init_package2();
    init_dist_es29();
    init_dist_es43();
    init_dist_es32();
    init_dist_es44();
    init_dist_es39();
    init_dist_es35();
    init_dist_es14();
    init_dist_es27();
    init_dist_es45();
    init_dist_es46();
    init_dist_es38();
    init_runtimeConfig_shared2();
    getRuntimeConfig4 = (config) => {
      emitWarningIfUnsupportedVersion2(process.version);
      const defaultsMode = resolveDefaultsModeConfig(config);
      const defaultConfigProvider = () => defaultsMode().then(loadConfigsForDefaultMode);
      const clientSharedValues = getRuntimeConfig3(config);
      emitWarningIfUnsupportedVersion(process.version);
      const loaderConfig = {
        profile: config?.profile,
        logger: clientSharedValues.logger
      };
      return {
        ...clientSharedValues,
        ...config,
        runtime: "node",
        defaultsMode,
        authSchemePreference: config?.authSchemePreference ?? loadConfig(NODE_AUTH_SCHEME_PREFERENCE_OPTIONS, loaderConfig),
        bodyLengthChecker: config?.bodyLengthChecker ?? calculateBodyLength,
        defaultUserAgentProvider: config?.defaultUserAgentProvider ?? createDefaultUserAgentProvider({ serviceId: clientSharedValues.serviceId, clientVersion: package_default3.version }),
        maxAttempts: config?.maxAttempts ?? loadConfig(NODE_MAX_ATTEMPT_CONFIG_OPTIONS, config),
        region: config?.region ?? loadConfig(NODE_REGION_CONFIG_OPTIONS, { ...NODE_REGION_CONFIG_FILE_OPTIONS, ...loaderConfig }),
        requestHandler: NodeHttpHandler.create(config?.requestHandler ?? defaultConfigProvider),
        retryMode: config?.retryMode ?? loadConfig({
          ...NODE_RETRY_MODE_CONFIG_OPTIONS,
          default: async () => (await defaultConfigProvider()).retryMode || DEFAULT_RETRY_MODE
        }, config),
        sha256: config?.sha256 ?? Hash.bind(null, "sha256"),
        streamCollector: config?.streamCollector ?? streamCollector,
        useDualstackEndpoint: config?.useDualstackEndpoint ?? loadConfig(NODE_USE_DUALSTACK_ENDPOINT_CONFIG_OPTIONS, loaderConfig),
        useFipsEndpoint: config?.useFipsEndpoint ?? loadConfig(NODE_USE_FIPS_ENDPOINT_CONFIG_OPTIONS, loaderConfig),
        userAgentAppId: config?.userAgentAppId ?? loadConfig(NODE_APP_ID_CONFIG_OPTIONS, loaderConfig)
      };
    };
  }
});

// node_modules/@aws-sdk/client-sso/dist-es/auth/httpAuthExtensionConfiguration.js
var getHttpAuthExtensionConfiguration2, resolveHttpAuthRuntimeConfig2;
var init_httpAuthExtensionConfiguration2 = __esm({
  "node_modules/@aws-sdk/client-sso/dist-es/auth/httpAuthExtensionConfiguration.js"() {
    getHttpAuthExtensionConfiguration2 = (runtimeConfig) => {
      const _httpAuthSchemes = runtimeConfig.httpAuthSchemes;
      let _httpAuthSchemeProvider = runtimeConfig.httpAuthSchemeProvider;
      let _credentials = runtimeConfig.credentials;
      return {
        setHttpAuthScheme(httpAuthScheme) {
          const index = _httpAuthSchemes.findIndex((scheme) => scheme.schemeId === httpAuthScheme.schemeId);
          if (index === -1) {
            _httpAuthSchemes.push(httpAuthScheme);
          } else {
            _httpAuthSchemes.splice(index, 1, httpAuthScheme);
          }
        },
        httpAuthSchemes() {
          return _httpAuthSchemes;
        },
        setHttpAuthSchemeProvider(httpAuthSchemeProvider) {
          _httpAuthSchemeProvider = httpAuthSchemeProvider;
        },
        httpAuthSchemeProvider() {
          return _httpAuthSchemeProvider;
        },
        setCredentials(credentials) {
          _credentials = credentials;
        },
        credentials() {
          return _credentials;
        }
      };
    };
    resolveHttpAuthRuntimeConfig2 = (config) => {
      return {
        httpAuthSchemes: config.httpAuthSchemes(),
        httpAuthSchemeProvider: config.httpAuthSchemeProvider(),
        credentials: config.credentials()
      };
    };
  }
});

// node_modules/@aws-sdk/client-sso/dist-es/runtimeExtensions.js
var resolveRuntimeExtensions2;
var init_runtimeExtensions2 = __esm({
  "node_modules/@aws-sdk/client-sso/dist-es/runtimeExtensions.js"() {
    init_dist_es47();
    init_dist_es2();
    init_dist_es27();
    init_httpAuthExtensionConfiguration2();
    resolveRuntimeExtensions2 = (runtimeConfig, extensions) => {
      const extensionConfiguration = Object.assign(getAwsRegionExtensionConfiguration(runtimeConfig), getDefaultExtensionConfiguration(runtimeConfig), getHttpHandlerExtensionConfiguration(runtimeConfig), getHttpAuthExtensionConfiguration2(runtimeConfig));
      extensions.forEach((extension) => extension.configure(extensionConfiguration));
      return Object.assign(runtimeConfig, resolveAwsRegionExtensionConfiguration(extensionConfiguration), resolveDefaultRuntimeConfig(extensionConfiguration), resolveHttpHandlerRuntimeConfig(extensionConfiguration), resolveHttpAuthRuntimeConfig2(extensionConfiguration));
    };
  }
});

// node_modules/@aws-sdk/client-sso/dist-es/SSOClient.js
var SSOClient;
var init_SSOClient = __esm({
  "node_modules/@aws-sdk/client-sso/dist-es/SSOClient.js"() {
    init_dist_es3();
    init_dist_es4();
    init_dist_es5();
    init_dist_es30();
    init_dist_es32();
    init_dist_es19();
    init_schema2();
    init_dist_es33();
    init_dist_es36();
    init_dist_es39();
    init_dist_es27();
    init_httpAuthSchemeProvider2();
    init_EndpointParameters2();
    init_runtimeConfig2();
    init_runtimeExtensions2();
    SSOClient = class extends Client {
      config;
      constructor(...[configuration]) {
        const _config_0 = getRuntimeConfig4(configuration || {});
        super(_config_0);
        this.initConfig = _config_0;
        const _config_1 = resolveClientEndpointParameters3(_config_0);
        const _config_2 = resolveUserAgentConfig(_config_1);
        const _config_3 = resolveRetryConfig(_config_2);
        const _config_4 = resolveRegionConfig(_config_3);
        const _config_5 = resolveHostHeaderConfig(_config_4);
        const _config_6 = resolveEndpointConfig(_config_5);
        const _config_7 = resolveHttpAuthSchemeConfig3(_config_6);
        const _config_8 = resolveRuntimeExtensions2(_config_7, configuration?.extensions || []);
        this.config = _config_8;
        this.middlewareStack.use(getSchemaSerdePlugin(this.config));
        this.middlewareStack.use(getUserAgentPlugin(this.config));
        this.middlewareStack.use(getRetryPlugin(this.config));
        this.middlewareStack.use(getContentLengthPlugin(this.config));
        this.middlewareStack.use(getHostHeaderPlugin(this.config));
        this.middlewareStack.use(getLoggerPlugin(this.config));
        this.middlewareStack.use(getRecursionDetectionPlugin(this.config));
        this.middlewareStack.use(getHttpAuthSchemeEndpointRuleSetPlugin(this.config, {
          httpAuthSchemeParametersProvider: defaultSSOHttpAuthSchemeParametersProvider,
          identityProviderConfigProvider: async (config) => new DefaultIdentityProviderConfig({
            "aws.auth#sigv4": config.credentials
          })
        }));
        this.middlewareStack.use(getHttpSigningPlugin(this.config));
      }
      destroy() {
        super.destroy();
      }
    };
  }
});

// node_modules/@aws-sdk/client-sso/dist-es/models/SSOServiceException.js
var SSOServiceException;
var init_SSOServiceException = __esm({
  "node_modules/@aws-sdk/client-sso/dist-es/models/SSOServiceException.js"() {
    init_dist_es27();
    SSOServiceException = class _SSOServiceException extends ServiceException {
      constructor(options) {
        super(options);
        Object.setPrototypeOf(this, _SSOServiceException.prototype);
      }
    };
  }
});

// node_modules/@aws-sdk/client-sso/dist-es/models/errors.js
var InvalidRequestException2, ResourceNotFoundException, TooManyRequestsException, UnauthorizedException;
var init_errors2 = __esm({
  "node_modules/@aws-sdk/client-sso/dist-es/models/errors.js"() {
    init_SSOServiceException();
    InvalidRequestException2 = class _InvalidRequestException extends SSOServiceException {
      name = "InvalidRequestException";
      $fault = "client";
      constructor(opts) {
        super({
          name: "InvalidRequestException",
          $fault: "client",
          ...opts
        });
        Object.setPrototypeOf(this, _InvalidRequestException.prototype);
      }
    };
    ResourceNotFoundException = class _ResourceNotFoundException extends SSOServiceException {
      name = "ResourceNotFoundException";
      $fault = "client";
      constructor(opts) {
        super({
          name: "ResourceNotFoundException",
          $fault: "client",
          ...opts
        });
        Object.setPrototypeOf(this, _ResourceNotFoundException.prototype);
      }
    };
    TooManyRequestsException = class _TooManyRequestsException extends SSOServiceException {
      name = "TooManyRequestsException";
      $fault = "client";
      constructor(opts) {
        super({
          name: "TooManyRequestsException",
          $fault: "client",
          ...opts
        });
        Object.setPrototypeOf(this, _TooManyRequestsException.prototype);
      }
    };
    UnauthorizedException = class _UnauthorizedException extends SSOServiceException {
      name = "UnauthorizedException";
      $fault = "client";
      constructor(opts) {
        super({
          name: "UnauthorizedException",
          $fault: "client",
          ...opts
        });
        Object.setPrototypeOf(this, _UnauthorizedException.prototype);
      }
    };
  }
});

// node_modules/@aws-sdk/client-sso/dist-es/schemas/schemas_0.js
var _AI, _ALT, _ATT, _GRC, _GRCR, _GRCRe, _IRE2, _L, _LA, _LAR, _LARR, _LARRi, _LARi, _LARis, _LR, _RC, _RI, _RLT, _RNFE, _SAKT, _STT, _TMRE, _UE, _aI, _aKI, _aL, _aN, _aT2, _ai, _c2, _e2, _eA, _ex, _h2, _hE2, _hH, _hQ, _m, _mR, _mr, _nT, _nt, _rC, _rL, _rN, _rn, _s2, _sAK, _sT, _xasbt, n02, AccessTokenType, SecretAccessKeyType, SessionTokenType, AccountInfo$, GetRoleCredentialsRequest$, GetRoleCredentialsResponse$, InvalidRequestException$2, ListAccountRolesRequest$, ListAccountRolesResponse$, ListAccountsRequest$, ListAccountsResponse$, LogoutRequest$, ResourceNotFoundException$, RoleCredentials$, RoleInfo$, TooManyRequestsException$, UnauthorizedException$, __Unit, SSOServiceException$, AccountListType, RoleListType, GetRoleCredentials$, ListAccountRoles$, ListAccounts$, Logout$;
var init_schemas_02 = __esm({
  "node_modules/@aws-sdk/client-sso/dist-es/schemas/schemas_0.js"() {
    init_schema2();
    init_errors2();
    init_SSOServiceException();
    _AI = "AccountInfo";
    _ALT = "AccountListType";
    _ATT = "AccessTokenType";
    _GRC = "GetRoleCredentials";
    _GRCR = "GetRoleCredentialsRequest";
    _GRCRe = "GetRoleCredentialsResponse";
    _IRE2 = "InvalidRequestException";
    _L = "Logout";
    _LA = "ListAccounts";
    _LAR = "ListAccountsRequest";
    _LARR = "ListAccountRolesRequest";
    _LARRi = "ListAccountRolesResponse";
    _LARi = "ListAccountsResponse";
    _LARis = "ListAccountRoles";
    _LR = "LogoutRequest";
    _RC = "RoleCredentials";
    _RI = "RoleInfo";
    _RLT = "RoleListType";
    _RNFE = "ResourceNotFoundException";
    _SAKT = "SecretAccessKeyType";
    _STT = "SessionTokenType";
    _TMRE = "TooManyRequestsException";
    _UE = "UnauthorizedException";
    _aI = "accountId";
    _aKI = "accessKeyId";
    _aL = "accountList";
    _aN = "accountName";
    _aT2 = "accessToken";
    _ai = "account_id";
    _c2 = "client";
    _e2 = "error";
    _eA = "emailAddress";
    _ex = "expiration";
    _h2 = "http";
    _hE2 = "httpError";
    _hH = "httpHeader";
    _hQ = "httpQuery";
    _m = "message";
    _mR = "maxResults";
    _mr = "max_result";
    _nT = "nextToken";
    _nt = "next_token";
    _rC = "roleCredentials";
    _rL = "roleList";
    _rN = "roleName";
    _rn = "role_name";
    _s2 = "smithy.ts.sdk.synthetic.com.amazonaws.sso";
    _sAK = "secretAccessKey";
    _sT = "sessionToken";
    _xasbt = "x-amz-sso_bearer_token";
    n02 = "com.amazonaws.sso";
    AccessTokenType = [0, n02, _ATT, 8, 0];
    SecretAccessKeyType = [0, n02, _SAKT, 8, 0];
    SessionTokenType = [0, n02, _STT, 8, 0];
    AccountInfo$ = [3, n02, _AI, 0, [_aI, _aN, _eA], [0, 0, 0]];
    GetRoleCredentialsRequest$ = [
      3,
      n02,
      _GRCR,
      0,
      [_rN, _aI, _aT2],
      [
        [0, { [_hQ]: _rn }],
        [0, { [_hQ]: _ai }],
        [() => AccessTokenType, { [_hH]: _xasbt }]
      ]
    ];
    GetRoleCredentialsResponse$ = [
      3,
      n02,
      _GRCRe,
      0,
      [_rC],
      [[() => RoleCredentials$, 0]]
    ];
    InvalidRequestException$2 = [-3, n02, _IRE2, { [_e2]: _c2, [_hE2]: 400 }, [_m], [0]];
    TypeRegistry.for(n02).registerError(InvalidRequestException$2, InvalidRequestException2);
    ListAccountRolesRequest$ = [
      3,
      n02,
      _LARR,
      0,
      [_nT, _mR, _aT2, _aI],
      [
        [0, { [_hQ]: _nt }],
        [1, { [_hQ]: _mr }],
        [() => AccessTokenType, { [_hH]: _xasbt }],
        [0, { [_hQ]: _ai }]
      ]
    ];
    ListAccountRolesResponse$ = [3, n02, _LARRi, 0, [_nT, _rL], [0, () => RoleListType]];
    ListAccountsRequest$ = [
      3,
      n02,
      _LAR,
      0,
      [_nT, _mR, _aT2],
      [
        [0, { [_hQ]: _nt }],
        [1, { [_hQ]: _mr }],
        [() => AccessTokenType, { [_hH]: _xasbt }]
      ]
    ];
    ListAccountsResponse$ = [3, n02, _LARi, 0, [_nT, _aL], [0, () => AccountListType]];
    LogoutRequest$ = [3, n02, _LR, 0, [_aT2], [[() => AccessTokenType, { [_hH]: _xasbt }]]];
    ResourceNotFoundException$ = [-3, n02, _RNFE, { [_e2]: _c2, [_hE2]: 404 }, [_m], [0]];
    TypeRegistry.for(n02).registerError(ResourceNotFoundException$, ResourceNotFoundException);
    RoleCredentials$ = [
      3,
      n02,
      _RC,
      0,
      [_aKI, _sAK, _sT, _ex],
      [0, [() => SecretAccessKeyType, 0], [() => SessionTokenType, 0], 1]
    ];
    RoleInfo$ = [3, n02, _RI, 0, [_rN, _aI], [0, 0]];
    TooManyRequestsException$ = [-3, n02, _TMRE, { [_e2]: _c2, [_hE2]: 429 }, [_m], [0]];
    TypeRegistry.for(n02).registerError(TooManyRequestsException$, TooManyRequestsException);
    UnauthorizedException$ = [-3, n02, _UE, { [_e2]: _c2, [_hE2]: 401 }, [_m], [0]];
    TypeRegistry.for(n02).registerError(UnauthorizedException$, UnauthorizedException);
    __Unit = "unit";
    SSOServiceException$ = [-3, _s2, "SSOServiceException", 0, [], []];
    TypeRegistry.for(_s2).registerError(SSOServiceException$, SSOServiceException);
    AccountListType = [1, n02, _ALT, 0, () => AccountInfo$];
    RoleListType = [1, n02, _RLT, 0, () => RoleInfo$];
    GetRoleCredentials$ = [
      9,
      n02,
      _GRC,
      { [_h2]: ["GET", "/federation/credentials", 200] },
      () => GetRoleCredentialsRequest$,
      () => GetRoleCredentialsResponse$
    ];
    ListAccountRoles$ = [
      9,
      n02,
      _LARis,
      { [_h2]: ["GET", "/assignment/roles", 200] },
      () => ListAccountRolesRequest$,
      () => ListAccountRolesResponse$
    ];
    ListAccounts$ = [
      9,
      n02,
      _LA,
      { [_h2]: ["GET", "/assignment/accounts", 200] },
      () => ListAccountsRequest$,
      () => ListAccountsResponse$
    ];
    Logout$ = [
      9,
      n02,
      _L,
      { [_h2]: ["POST", "/logout", 200] },
      () => LogoutRequest$,
      () => __Unit
    ];
  }
});

// node_modules/@aws-sdk/client-sso/dist-es/commands/GetRoleCredentialsCommand.js
var GetRoleCredentialsCommand;
var init_GetRoleCredentialsCommand = __esm({
  "node_modules/@aws-sdk/client-sso/dist-es/commands/GetRoleCredentialsCommand.js"() {
    init_dist_es36();
    init_dist_es27();
    init_EndpointParameters2();
    init_schemas_02();
    GetRoleCredentialsCommand = class extends Command.classBuilder().ep(commonParams3).m(function(Command2, cs, config, o6) {
      return [getEndpointPlugin(config, Command2.getEndpointParameterInstructions())];
    }).s("SWBPortalService", "GetRoleCredentials", {}).n("SSOClient", "GetRoleCredentialsCommand").sc(GetRoleCredentials$).build() {
    };
  }
});

// node_modules/@aws-sdk/client-sso/dist-es/commands/ListAccountRolesCommand.js
var ListAccountRolesCommand;
var init_ListAccountRolesCommand = __esm({
  "node_modules/@aws-sdk/client-sso/dist-es/commands/ListAccountRolesCommand.js"() {
    init_dist_es36();
    init_dist_es27();
    init_EndpointParameters2();
    init_schemas_02();
    ListAccountRolesCommand = class extends Command.classBuilder().ep(commonParams3).m(function(Command2, cs, config, o6) {
      return [getEndpointPlugin(config, Command2.getEndpointParameterInstructions())];
    }).s("SWBPortalService", "ListAccountRoles", {}).n("SSOClient", "ListAccountRolesCommand").sc(ListAccountRoles$).build() {
    };
  }
});

// node_modules/@aws-sdk/client-sso/dist-es/commands/ListAccountsCommand.js
var ListAccountsCommand;
var init_ListAccountsCommand = __esm({
  "node_modules/@aws-sdk/client-sso/dist-es/commands/ListAccountsCommand.js"() {
    init_dist_es36();
    init_dist_es27();
    init_EndpointParameters2();
    init_schemas_02();
    ListAccountsCommand = class extends Command.classBuilder().ep(commonParams3).m(function(Command2, cs, config, o6) {
      return [getEndpointPlugin(config, Command2.getEndpointParameterInstructions())];
    }).s("SWBPortalService", "ListAccounts", {}).n("SSOClient", "ListAccountsCommand").sc(ListAccounts$).build() {
    };
  }
});

// node_modules/@aws-sdk/client-sso/dist-es/commands/LogoutCommand.js
var LogoutCommand;
var init_LogoutCommand = __esm({
  "node_modules/@aws-sdk/client-sso/dist-es/commands/LogoutCommand.js"() {
    init_dist_es36();
    init_dist_es27();
    init_EndpointParameters2();
    init_schemas_02();
    LogoutCommand = class extends Command.classBuilder().ep(commonParams3).m(function(Command2, cs, config, o6) {
      return [getEndpointPlugin(config, Command2.getEndpointParameterInstructions())];
    }).s("SWBPortalService", "Logout", {}).n("SSOClient", "LogoutCommand").sc(Logout$).build() {
    };
  }
});

// node_modules/@aws-sdk/client-sso/dist-es/SSO.js
var commands2, SSO;
var init_SSO = __esm({
  "node_modules/@aws-sdk/client-sso/dist-es/SSO.js"() {
    init_dist_es27();
    init_GetRoleCredentialsCommand();
    init_ListAccountRolesCommand();
    init_ListAccountsCommand();
    init_LogoutCommand();
    init_SSOClient();
    commands2 = {
      GetRoleCredentialsCommand,
      ListAccountRolesCommand,
      ListAccountsCommand,
      LogoutCommand
    };
    SSO = class extends SSOClient {
    };
    createAggregatedClient(commands2, SSO);
  }
});

// node_modules/@aws-sdk/client-sso/dist-es/commands/index.js
var init_commands2 = __esm({
  "node_modules/@aws-sdk/client-sso/dist-es/commands/index.js"() {
    init_GetRoleCredentialsCommand();
    init_ListAccountRolesCommand();
    init_ListAccountsCommand();
    init_LogoutCommand();
  }
});

// node_modules/@aws-sdk/client-sso/dist-es/pagination/Interfaces.js
var init_Interfaces = __esm({
  "node_modules/@aws-sdk/client-sso/dist-es/pagination/Interfaces.js"() {
  }
});

// node_modules/@aws-sdk/client-sso/dist-es/pagination/ListAccountRolesPaginator.js
var paginateListAccountRoles;
var init_ListAccountRolesPaginator = __esm({
  "node_modules/@aws-sdk/client-sso/dist-es/pagination/ListAccountRolesPaginator.js"() {
    init_dist_es19();
    init_ListAccountRolesCommand();
    init_SSOClient();
    paginateListAccountRoles = createPaginator(SSOClient, ListAccountRolesCommand, "nextToken", "nextToken", "maxResults");
  }
});

// node_modules/@aws-sdk/client-sso/dist-es/pagination/ListAccountsPaginator.js
var paginateListAccounts;
var init_ListAccountsPaginator = __esm({
  "node_modules/@aws-sdk/client-sso/dist-es/pagination/ListAccountsPaginator.js"() {
    init_dist_es19();
    init_ListAccountsCommand();
    init_SSOClient();
    paginateListAccounts = createPaginator(SSOClient, ListAccountsCommand, "nextToken", "nextToken", "maxResults");
  }
});

// node_modules/@aws-sdk/client-sso/dist-es/pagination/index.js
var init_pagination2 = __esm({
  "node_modules/@aws-sdk/client-sso/dist-es/pagination/index.js"() {
    init_Interfaces();
    init_ListAccountRolesPaginator();
    init_ListAccountsPaginator();
  }
});

// node_modules/@aws-sdk/client-sso/dist-es/models/models_0.js
var init_models_02 = __esm({
  "node_modules/@aws-sdk/client-sso/dist-es/models/models_0.js"() {
  }
});

// node_modules/@aws-sdk/client-sso/dist-es/index.js
var init_dist_es49 = __esm({
  "node_modules/@aws-sdk/client-sso/dist-es/index.js"() {
    init_SSOClient();
    init_SSO();
    init_commands2();
    init_schemas_02();
    init_pagination2();
    init_errors2();
    init_models_02();
  }
});

// node_modules/@aws-sdk/credential-provider-sso/dist-es/loadSso.js
var loadSso_exports = {};
__export(loadSso_exports, {
  GetRoleCredentialsCommand: () => GetRoleCredentialsCommand,
  SSOClient: () => SSOClient
});
var init_loadSso = __esm({
  "node_modules/@aws-sdk/credential-provider-sso/dist-es/loadSso.js"() {
    init_dist_es49();
  }
});

// node_modules/@aws-sdk/credential-provider-sso/dist-es/resolveSSOCredentials.js
var SHOULD_FAIL_CREDENTIAL_CHAIN, resolveSSOCredentials;
var init_resolveSSOCredentials = __esm({
  "node_modules/@aws-sdk/credential-provider-sso/dist-es/resolveSSOCredentials.js"() {
    init_client2();
    init_dist_es48();
    init_dist_es24();
    init_dist_es34();
    SHOULD_FAIL_CREDENTIAL_CHAIN = false;
    resolveSSOCredentials = async ({ ssoStartUrl, ssoSession, ssoAccountId, ssoRegion, ssoRoleName, ssoClient, clientConfig, parentClientConfig, callerClientConfig, profile, filepath, configFilepath, ignoreCache, logger: logger2 }) => {
      let token;
      const refreshMessage = `To refresh this SSO session run aws sso login with the corresponding profile.`;
      if (ssoSession) {
        try {
          const _token = await fromSso({
            profile,
            filepath,
            configFilepath,
            ignoreCache
          })();
          token = {
            accessToken: _token.token,
            expiresAt: new Date(_token.expiration).toISOString()
          };
        } catch (e6) {
          throw new CredentialsProviderError(e6.message, {
            tryNextLink: SHOULD_FAIL_CREDENTIAL_CHAIN,
            logger: logger2
          });
        }
      } else {
        try {
          token = await getSSOTokenFromFile(ssoStartUrl);
        } catch (e6) {
          throw new CredentialsProviderError(`The SSO session associated with this profile is invalid. ${refreshMessage}`, {
            tryNextLink: SHOULD_FAIL_CREDENTIAL_CHAIN,
            logger: logger2
          });
        }
      }
      if (new Date(token.expiresAt).getTime() - Date.now() <= 0) {
        throw new CredentialsProviderError(`The SSO session associated with this profile has expired. ${refreshMessage}`, {
          tryNextLink: SHOULD_FAIL_CREDENTIAL_CHAIN,
          logger: logger2
        });
      }
      const { accessToken } = token;
      const { SSOClient: SSOClient2, GetRoleCredentialsCommand: GetRoleCredentialsCommand2 } = await Promise.resolve().then(() => (init_loadSso(), loadSso_exports));
      const sso = ssoClient || new SSOClient2(Object.assign({}, clientConfig ?? {}, {
        logger: clientConfig?.logger ?? callerClientConfig?.logger ?? parentClientConfig?.logger,
        region: clientConfig?.region ?? ssoRegion,
        userAgentAppId: clientConfig?.userAgentAppId ?? callerClientConfig?.userAgentAppId ?? parentClientConfig?.userAgentAppId
      }));
      let ssoResp;
      try {
        ssoResp = await sso.send(new GetRoleCredentialsCommand2({
          accountId: ssoAccountId,
          roleName: ssoRoleName,
          accessToken
        }));
      } catch (e6) {
        throw new CredentialsProviderError(e6, {
          tryNextLink: SHOULD_FAIL_CREDENTIAL_CHAIN,
          logger: logger2
        });
      }
      const { roleCredentials: { accessKeyId, secretAccessKey, sessionToken, expiration, credentialScope, accountId } = {} } = ssoResp;
      if (!accessKeyId || !secretAccessKey || !sessionToken || !expiration) {
        throw new CredentialsProviderError("SSO returns an invalid temporary credential.", {
          tryNextLink: SHOULD_FAIL_CREDENTIAL_CHAIN,
          logger: logger2
        });
      }
      const credentials = {
        accessKeyId,
        secretAccessKey,
        sessionToken,
        expiration: new Date(expiration),
        ...credentialScope && { credentialScope },
        ...accountId && { accountId }
      };
      if (ssoSession) {
        setCredentialFeature(credentials, "CREDENTIALS_SSO", "s");
      } else {
        setCredentialFeature(credentials, "CREDENTIALS_SSO_LEGACY", "u");
      }
      return credentials;
    };
  }
});

// node_modules/@aws-sdk/credential-provider-sso/dist-es/validateSsoProfile.js
var validateSsoProfile;
var init_validateSsoProfile = __esm({
  "node_modules/@aws-sdk/credential-provider-sso/dist-es/validateSsoProfile.js"() {
    init_dist_es24();
    validateSsoProfile = (profile, logger2) => {
      const { sso_start_url, sso_account_id, sso_region, sso_role_name } = profile;
      if (!sso_start_url || !sso_account_id || !sso_region || !sso_role_name) {
        throw new CredentialsProviderError(`Profile is configured with invalid SSO credentials. Required parameters "sso_account_id", "sso_region", "sso_role_name", "sso_start_url". Got ${Object.keys(profile).join(", ")}
Reference: https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html`, { tryNextLink: false, logger: logger2 });
      }
      return profile;
    };
  }
});

// node_modules/@aws-sdk/credential-provider-sso/dist-es/fromSSO.js
var fromSSO;
var init_fromSSO = __esm({
  "node_modules/@aws-sdk/credential-provider-sso/dist-es/fromSSO.js"() {
    init_dist_es24();
    init_dist_es34();
    init_isSsoProfile();
    init_resolveSSOCredentials();
    init_validateSsoProfile();
    fromSSO = (init = {}) => async ({ callerClientConfig } = {}) => {
      init.logger?.debug("@aws-sdk/credential-provider-sso - fromSSO");
      const { ssoStartUrl, ssoAccountId, ssoRegion, ssoRoleName, ssoSession } = init;
      const { ssoClient } = init;
      const profileName = getProfileName({
        profile: init.profile ?? callerClientConfig?.profile
      });
      if (!ssoStartUrl && !ssoAccountId && !ssoRegion && !ssoRoleName && !ssoSession) {
        const profiles = await parseKnownFiles(init);
        const profile = profiles[profileName];
        if (!profile) {
          throw new CredentialsProviderError(`Profile ${profileName} was not found.`, { logger: init.logger });
        }
        if (!isSsoProfile(profile)) {
          throw new CredentialsProviderError(`Profile ${profileName} is not configured with SSO credentials.`, {
            logger: init.logger
          });
        }
        if (profile?.sso_session) {
          const ssoSessions = await loadSsoSessionData(init);
          const session = ssoSessions[profile.sso_session];
          const conflictMsg = ` configurations in profile ${profileName} and sso-session ${profile.sso_session}`;
          if (ssoRegion && ssoRegion !== session.sso_region) {
            throw new CredentialsProviderError(`Conflicting SSO region` + conflictMsg, {
              tryNextLink: false,
              logger: init.logger
            });
          }
          if (ssoStartUrl && ssoStartUrl !== session.sso_start_url) {
            throw new CredentialsProviderError(`Conflicting SSO start_url` + conflictMsg, {
              tryNextLink: false,
              logger: init.logger
            });
          }
          profile.sso_region = session.sso_region;
          profile.sso_start_url = session.sso_start_url;
        }
        const { sso_start_url, sso_account_id, sso_region, sso_role_name, sso_session } = validateSsoProfile(profile, init.logger);
        return resolveSSOCredentials({
          ssoStartUrl: sso_start_url,
          ssoSession: sso_session,
          ssoAccountId: sso_account_id,
          ssoRegion: sso_region,
          ssoRoleName: sso_role_name,
          ssoClient,
          clientConfig: init.clientConfig,
          parentClientConfig: init.parentClientConfig,
          callerClientConfig: init.callerClientConfig,
          profile: profileName,
          filepath: init.filepath,
          configFilepath: init.configFilepath,
          ignoreCache: init.ignoreCache,
          logger: init.logger
        });
      } else if (!ssoStartUrl || !ssoAccountId || !ssoRegion || !ssoRoleName) {
        throw new CredentialsProviderError('Incomplete configuration. The fromSSO() argument hash must include "ssoStartUrl", "ssoAccountId", "ssoRegion", "ssoRoleName"', { tryNextLink: false, logger: init.logger });
      } else {
        return resolveSSOCredentials({
          ssoStartUrl,
          ssoSession,
          ssoAccountId,
          ssoRegion,
          ssoRoleName,
          ssoClient,
          clientConfig: init.clientConfig,
          parentClientConfig: init.parentClientConfig,
          callerClientConfig: init.callerClientConfig,
          profile: profileName,
          filepath: init.filepath,
          configFilepath: init.configFilepath,
          ignoreCache: init.ignoreCache,
          logger: init.logger
        });
      }
    };
  }
});

// node_modules/@aws-sdk/credential-provider-sso/dist-es/types.js
var init_types9 = __esm({
  "node_modules/@aws-sdk/credential-provider-sso/dist-es/types.js"() {
  }
});

// node_modules/@aws-sdk/credential-provider-sso/dist-es/index.js
var dist_es_exports4 = {};
__export(dist_es_exports4, {
  fromSSO: () => fromSSO,
  isSsoProfile: () => isSsoProfile,
  validateSsoProfile: () => validateSsoProfile
});
var init_dist_es50 = __esm({
  "node_modules/@aws-sdk/credential-provider-sso/dist-es/index.js"() {
    init_fromSSO();
    init_isSsoProfile();
    init_types9();
    init_validateSsoProfile();
  }
});

// node_modules/@aws-sdk/credential-provider-ini/dist-es/resolveCredentialSource.js
var resolveCredentialSource, setNamedProvider;
var init_resolveCredentialSource = __esm({
  "node_modules/@aws-sdk/credential-provider-ini/dist-es/resolveCredentialSource.js"() {
    init_client2();
    init_dist_es24();
    resolveCredentialSource = (credentialSource, profileName, logger2) => {
      const sourceProvidersMap = {
        EcsContainer: async (options) => {
          const { fromHttp: fromHttp2 } = await Promise.resolve().then(() => (init_dist_es42(), dist_es_exports3));
          const { fromContainerMetadata: fromContainerMetadata2 } = await Promise.resolve().then(() => (init_dist_es41(), dist_es_exports2));
          logger2?.debug("@aws-sdk/credential-provider-ini - credential_source is EcsContainer");
          return async () => chain(fromHttp2(options ?? {}), fromContainerMetadata2(options))().then(setNamedProvider);
        },
        Ec2InstanceMetadata: async (options) => {
          logger2?.debug("@aws-sdk/credential-provider-ini - credential_source is Ec2InstanceMetadata");
          const { fromInstanceMetadata: fromInstanceMetadata2 } = await Promise.resolve().then(() => (init_dist_es41(), dist_es_exports2));
          return async () => fromInstanceMetadata2(options)().then(setNamedProvider);
        },
        Environment: async (options) => {
          logger2?.debug("@aws-sdk/credential-provider-ini - credential_source is Environment");
          const { fromEnv: fromEnv3 } = await Promise.resolve().then(() => (init_dist_es40(), dist_es_exports));
          return async () => fromEnv3(options)().then(setNamedProvider);
        }
      };
      if (credentialSource in sourceProvidersMap) {
        return sourceProvidersMap[credentialSource];
      } else {
        throw new CredentialsProviderError(`Unsupported credential source in profile ${profileName}. Got ${credentialSource}, expected EcsContainer or Ec2InstanceMetadata or Environment.`, { logger: logger2 });
      }
    };
    setNamedProvider = (creds) => setCredentialFeature(creds, "CREDENTIALS_PROFILE_NAMED_PROVIDER", "p");
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/auth/httpAuthSchemeProvider.js
function createAwsAuthSigv4HttpAuthOption4(authParameters) {
  return {
    schemeId: "aws.auth#sigv4",
    signingProperties: {
      name: "sts",
      region: authParameters.region
    },
    propertiesExtractor: (config, context) => ({
      signingProperties: {
        config,
        context
      }
    })
  };
}
function createSmithyApiNoAuthHttpAuthOption3(authParameters) {
  return {
    schemeId: "smithy.api#noAuth"
  };
}
var defaultSTSHttpAuthSchemeParametersProvider, defaultSTSHttpAuthSchemeProvider, resolveStsAuthConfig, resolveHttpAuthSchemeConfig4;
var init_httpAuthSchemeProvider3 = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/auth/httpAuthSchemeProvider.js"() {
    init_dist_es29();
    init_dist_es6();
    init_STSClient();
    defaultSTSHttpAuthSchemeParametersProvider = async (config, context, input) => {
      return {
        operation: getSmithyContext(context).operation,
        region: await normalizeProvider(config.region)() || (() => {
          throw new Error("expected `region` to be configured for `aws.auth#sigv4`");
        })()
      };
    };
    defaultSTSHttpAuthSchemeProvider = (authParameters) => {
      const options = [];
      switch (authParameters.operation) {
        case "AssumeRoleWithWebIdentity": {
          options.push(createSmithyApiNoAuthHttpAuthOption3(authParameters));
          break;
        }
        default: {
          options.push(createAwsAuthSigv4HttpAuthOption4(authParameters));
        }
      }
      return options;
    };
    resolveStsAuthConfig = (input) => Object.assign(input, {
      stsClientCtor: STSClient
    });
    resolveHttpAuthSchemeConfig4 = (config) => {
      const config_0 = resolveStsAuthConfig(config);
      const config_1 = resolveAwsSdkSigV4Config(config_0);
      return Object.assign(config_1, {
        authSchemePreference: normalizeProvider(config.authSchemePreference ?? [])
      });
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/endpoint/EndpointParameters.js
var resolveClientEndpointParameters4, commonParams4;
var init_EndpointParameters3 = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/endpoint/EndpointParameters.js"() {
    resolveClientEndpointParameters4 = (options) => {
      return Object.assign(options, {
        useDualstackEndpoint: options.useDualstackEndpoint ?? false,
        useFipsEndpoint: options.useFipsEndpoint ?? false,
        useGlobalEndpoint: options.useGlobalEndpoint ?? false,
        defaultSigningName: "sts"
      });
    };
    commonParams4 = {
      UseGlobalEndpoint: { type: "builtInParams", name: "useGlobalEndpoint" },
      UseFIPS: { type: "builtInParams", name: "useFipsEndpoint" },
      Endpoint: { type: "builtInParams", name: "endpoint" },
      Region: { type: "builtInParams", name: "region" },
      UseDualStack: { type: "builtInParams", name: "useDualstackEndpoint" }
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/endpoint/ruleset.js
var F, G, H, I, J, a3, b3, c3, d3, e3, f3, g3, h3, i3, j3, k3, l3, m3, n3, o3, p3, q3, r3, s3, t3, u3, v3, w3, x3, y, z, A, B, C, D, E, _data3, ruleSet3;
var init_ruleset3 = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/endpoint/ruleset.js"() {
    F = "required";
    G = "type";
    H = "fn";
    I = "argv";
    J = "ref";
    a3 = false;
    b3 = true;
    c3 = "booleanEquals";
    d3 = "stringEquals";
    e3 = "sigv4";
    f3 = "sts";
    g3 = "us-east-1";
    h3 = "endpoint";
    i3 = "https://sts.{Region}.{PartitionResult#dnsSuffix}";
    j3 = "tree";
    k3 = "error";
    l3 = "getAttr";
    m3 = { [F]: false, [G]: "string" };
    n3 = { [F]: true, "default": false, [G]: "boolean" };
    o3 = { [J]: "Endpoint" };
    p3 = { [H]: "isSet", [I]: [{ [J]: "Region" }] };
    q3 = { [J]: "Region" };
    r3 = { [H]: "aws.partition", [I]: [q3], "assign": "PartitionResult" };
    s3 = { [J]: "UseFIPS" };
    t3 = { [J]: "UseDualStack" };
    u3 = { "url": "https://sts.amazonaws.com", "properties": { "authSchemes": [{ "name": e3, "signingName": f3, "signingRegion": g3 }] }, "headers": {} };
    v3 = {};
    w3 = { "conditions": [{ [H]: d3, [I]: [q3, "aws-global"] }], [h3]: u3, [G]: h3 };
    x3 = { [H]: c3, [I]: [s3, true] };
    y = { [H]: c3, [I]: [t3, true] };
    z = { [H]: l3, [I]: [{ [J]: "PartitionResult" }, "supportsFIPS"] };
    A = { [J]: "PartitionResult" };
    B = { [H]: c3, [I]: [true, { [H]: l3, [I]: [A, "supportsDualStack"] }] };
    C = [{ [H]: "isSet", [I]: [o3] }];
    D = [x3];
    E = [y];
    _data3 = { version: "1.0", parameters: { Region: m3, UseDualStack: n3, UseFIPS: n3, Endpoint: m3, UseGlobalEndpoint: n3 }, rules: [{ conditions: [{ [H]: c3, [I]: [{ [J]: "UseGlobalEndpoint" }, b3] }, { [H]: "not", [I]: C }, p3, r3, { [H]: c3, [I]: [s3, a3] }, { [H]: c3, [I]: [t3, a3] }], rules: [{ conditions: [{ [H]: d3, [I]: [q3, "ap-northeast-1"] }], endpoint: u3, [G]: h3 }, { conditions: [{ [H]: d3, [I]: [q3, "ap-south-1"] }], endpoint: u3, [G]: h3 }, { conditions: [{ [H]: d3, [I]: [q3, "ap-southeast-1"] }], endpoint: u3, [G]: h3 }, { conditions: [{ [H]: d3, [I]: [q3, "ap-southeast-2"] }], endpoint: u3, [G]: h3 }, w3, { conditions: [{ [H]: d3, [I]: [q3, "ca-central-1"] }], endpoint: u3, [G]: h3 }, { conditions: [{ [H]: d3, [I]: [q3, "eu-central-1"] }], endpoint: u3, [G]: h3 }, { conditions: [{ [H]: d3, [I]: [q3, "eu-north-1"] }], endpoint: u3, [G]: h3 }, { conditions: [{ [H]: d3, [I]: [q3, "eu-west-1"] }], endpoint: u3, [G]: h3 }, { conditions: [{ [H]: d3, [I]: [q3, "eu-west-2"] }], endpoint: u3, [G]: h3 }, { conditions: [{ [H]: d3, [I]: [q3, "eu-west-3"] }], endpoint: u3, [G]: h3 }, { conditions: [{ [H]: d3, [I]: [q3, "sa-east-1"] }], endpoint: u3, [G]: h3 }, { conditions: [{ [H]: d3, [I]: [q3, g3] }], endpoint: u3, [G]: h3 }, { conditions: [{ [H]: d3, [I]: [q3, "us-east-2"] }], endpoint: u3, [G]: h3 }, { conditions: [{ [H]: d3, [I]: [q3, "us-west-1"] }], endpoint: u3, [G]: h3 }, { conditions: [{ [H]: d3, [I]: [q3, "us-west-2"] }], endpoint: u3, [G]: h3 }, { endpoint: { url: i3, properties: { authSchemes: [{ name: e3, signingName: f3, signingRegion: "{Region}" }] }, headers: v3 }, [G]: h3 }], [G]: j3 }, { conditions: C, rules: [{ conditions: D, error: "Invalid Configuration: FIPS and custom endpoint are not supported", [G]: k3 }, { conditions: E, error: "Invalid Configuration: Dualstack and custom endpoint are not supported", [G]: k3 }, { endpoint: { url: o3, properties: v3, headers: v3 }, [G]: h3 }], [G]: j3 }, { conditions: [p3], rules: [{ conditions: [r3], rules: [{ conditions: [x3, y], rules: [{ conditions: [{ [H]: c3, [I]: [b3, z] }, B], rules: [{ endpoint: { url: "https://sts-fips.{Region}.{PartitionResult#dualStackDnsSuffix}", properties: v3, headers: v3 }, [G]: h3 }], [G]: j3 }, { error: "FIPS and DualStack are enabled, but this partition does not support one or both", [G]: k3 }], [G]: j3 }, { conditions: D, rules: [{ conditions: [{ [H]: c3, [I]: [z, b3] }], rules: [{ conditions: [{ [H]: d3, [I]: [{ [H]: l3, [I]: [A, "name"] }, "aws-us-gov"] }], endpoint: { url: "https://sts.{Region}.amazonaws.com", properties: v3, headers: v3 }, [G]: h3 }, { endpoint: { url: "https://sts-fips.{Region}.{PartitionResult#dnsSuffix}", properties: v3, headers: v3 }, [G]: h3 }], [G]: j3 }, { error: "FIPS is enabled but this partition does not support FIPS", [G]: k3 }], [G]: j3 }, { conditions: E, rules: [{ conditions: [B], rules: [{ endpoint: { url: "https://sts.{Region}.{PartitionResult#dualStackDnsSuffix}", properties: v3, headers: v3 }, [G]: h3 }], [G]: j3 }, { error: "DualStack is enabled but this partition does not support DualStack", [G]: k3 }], [G]: j3 }, w3, { endpoint: { url: i3, properties: v3, headers: v3 }, [G]: h3 }], [G]: j3 }], [G]: j3 }, { error: "Invalid Configuration: Missing Region", [G]: k3 }] };
    ruleSet3 = _data3;
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/endpoint/endpointResolver.js
var cache3, defaultEndpointResolver3;
var init_endpointResolver3 = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/endpoint/endpointResolver.js"() {
    init_dist_es23();
    init_dist_es20();
    init_ruleset3();
    cache3 = new EndpointCache({
      size: 50,
      params: ["Endpoint", "Region", "UseDualStack", "UseFIPS", "UseGlobalEndpoint"]
    });
    defaultEndpointResolver3 = (endpointParams, context = {}) => {
      return cache3.get(endpointParams, () => resolveEndpoint(ruleSet3, {
        endpointParams,
        logger: context.logger
      }));
    };
    customEndpointFunctions.aws = awsEndpointFunctions;
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/runtimeConfig.shared.js
var getRuntimeConfig5;
var init_runtimeConfig_shared3 = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/runtimeConfig.shared.js"() {
    init_dist_es29();
    init_protocols2();
    init_dist_es19();
    init_dist_es27();
    init_dist_es22();
    init_dist_es11();
    init_dist_es10();
    init_httpAuthSchemeProvider3();
    init_endpointResolver3();
    getRuntimeConfig5 = (config) => {
      return {
        apiVersion: "2011-06-15",
        base64Decoder: config?.base64Decoder ?? fromBase64,
        base64Encoder: config?.base64Encoder ?? toBase64,
        disableHostPrefix: config?.disableHostPrefix ?? false,
        endpointProvider: config?.endpointProvider ?? defaultEndpointResolver3,
        extensions: config?.extensions ?? [],
        httpAuthSchemeProvider: config?.httpAuthSchemeProvider ?? defaultSTSHttpAuthSchemeProvider,
        httpAuthSchemes: config?.httpAuthSchemes ?? [
          {
            schemeId: "aws.auth#sigv4",
            identityProvider: (ipc) => ipc.getIdentityProvider("aws.auth#sigv4"),
            signer: new AwsSdkSigV4Signer()
          },
          {
            schemeId: "smithy.api#noAuth",
            identityProvider: (ipc) => ipc.getIdentityProvider("smithy.api#noAuth") || (async () => ({})),
            signer: new NoAuthSigner()
          }
        ],
        logger: config?.logger ?? new NoOpLogger(),
        protocol: config?.protocol ?? AwsQueryProtocol,
        protocolSettings: config?.protocolSettings ?? {
          defaultNamespace: "com.amazonaws.sts",
          xmlNamespace: "https://sts.amazonaws.com/doc/2011-06-15/",
          version: "2011-06-15",
          serviceTarget: "AWSSecurityTokenServiceV20110615"
        },
        serviceId: config?.serviceId ?? "STS",
        urlParser: config?.urlParser ?? parseUrl,
        utf8Decoder: config?.utf8Decoder ?? fromUtf8,
        utf8Encoder: config?.utf8Encoder ?? toUtf8
      };
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/runtimeConfig.js
var getRuntimeConfig6;
var init_runtimeConfig3 = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/runtimeConfig.js"() {
    init_package();
    init_dist_es29();
    init_dist_es43();
    init_dist_es32();
    init_dist_es19();
    init_dist_es44();
    init_dist_es39();
    init_dist_es35();
    init_dist_es14();
    init_dist_es27();
    init_dist_es45();
    init_dist_es46();
    init_dist_es38();
    init_runtimeConfig_shared3();
    getRuntimeConfig6 = (config) => {
      emitWarningIfUnsupportedVersion2(process.version);
      const defaultsMode = resolveDefaultsModeConfig(config);
      const defaultConfigProvider = () => defaultsMode().then(loadConfigsForDefaultMode);
      const clientSharedValues = getRuntimeConfig5(config);
      emitWarningIfUnsupportedVersion(process.version);
      const loaderConfig = {
        profile: config?.profile,
        logger: clientSharedValues.logger
      };
      return {
        ...clientSharedValues,
        ...config,
        runtime: "node",
        defaultsMode,
        authSchemePreference: config?.authSchemePreference ?? loadConfig(NODE_AUTH_SCHEME_PREFERENCE_OPTIONS, loaderConfig),
        bodyLengthChecker: config?.bodyLengthChecker ?? calculateBodyLength,
        defaultUserAgentProvider: config?.defaultUserAgentProvider ?? createDefaultUserAgentProvider({ serviceId: clientSharedValues.serviceId, clientVersion: package_default2.version }),
        httpAuthSchemes: config?.httpAuthSchemes ?? [
          {
            schemeId: "aws.auth#sigv4",
            identityProvider: (ipc) => ipc.getIdentityProvider("aws.auth#sigv4") || (async (idProps) => await config.credentialDefaultProvider(idProps?.__config || {})()),
            signer: new AwsSdkSigV4Signer()
          },
          {
            schemeId: "smithy.api#noAuth",
            identityProvider: (ipc) => ipc.getIdentityProvider("smithy.api#noAuth") || (async () => ({})),
            signer: new NoAuthSigner()
          }
        ],
        maxAttempts: config?.maxAttempts ?? loadConfig(NODE_MAX_ATTEMPT_CONFIG_OPTIONS, config),
        region: config?.region ?? loadConfig(NODE_REGION_CONFIG_OPTIONS, { ...NODE_REGION_CONFIG_FILE_OPTIONS, ...loaderConfig }),
        requestHandler: NodeHttpHandler.create(config?.requestHandler ?? defaultConfigProvider),
        retryMode: config?.retryMode ?? loadConfig({
          ...NODE_RETRY_MODE_CONFIG_OPTIONS,
          default: async () => (await defaultConfigProvider()).retryMode || DEFAULT_RETRY_MODE
        }, config),
        sha256: config?.sha256 ?? Hash.bind(null, "sha256"),
        streamCollector: config?.streamCollector ?? streamCollector,
        useDualstackEndpoint: config?.useDualstackEndpoint ?? loadConfig(NODE_USE_DUALSTACK_ENDPOINT_CONFIG_OPTIONS, loaderConfig),
        useFipsEndpoint: config?.useFipsEndpoint ?? loadConfig(NODE_USE_FIPS_ENDPOINT_CONFIG_OPTIONS, loaderConfig),
        userAgentAppId: config?.userAgentAppId ?? loadConfig(NODE_APP_ID_CONFIG_OPTIONS, loaderConfig)
      };
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/auth/httpAuthExtensionConfiguration.js
var getHttpAuthExtensionConfiguration3, resolveHttpAuthRuntimeConfig3;
var init_httpAuthExtensionConfiguration3 = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/auth/httpAuthExtensionConfiguration.js"() {
    getHttpAuthExtensionConfiguration3 = (runtimeConfig) => {
      const _httpAuthSchemes = runtimeConfig.httpAuthSchemes;
      let _httpAuthSchemeProvider = runtimeConfig.httpAuthSchemeProvider;
      let _credentials = runtimeConfig.credentials;
      return {
        setHttpAuthScheme(httpAuthScheme) {
          const index = _httpAuthSchemes.findIndex((scheme) => scheme.schemeId === httpAuthScheme.schemeId);
          if (index === -1) {
            _httpAuthSchemes.push(httpAuthScheme);
          } else {
            _httpAuthSchemes.splice(index, 1, httpAuthScheme);
          }
        },
        httpAuthSchemes() {
          return _httpAuthSchemes;
        },
        setHttpAuthSchemeProvider(httpAuthSchemeProvider) {
          _httpAuthSchemeProvider = httpAuthSchemeProvider;
        },
        httpAuthSchemeProvider() {
          return _httpAuthSchemeProvider;
        },
        setCredentials(credentials) {
          _credentials = credentials;
        },
        credentials() {
          return _credentials;
        }
      };
    };
    resolveHttpAuthRuntimeConfig3 = (config) => {
      return {
        httpAuthSchemes: config.httpAuthSchemes(),
        httpAuthSchemeProvider: config.httpAuthSchemeProvider(),
        credentials: config.credentials()
      };
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/runtimeExtensions.js
var resolveRuntimeExtensions3;
var init_runtimeExtensions3 = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/runtimeExtensions.js"() {
    init_dist_es47();
    init_dist_es2();
    init_dist_es27();
    init_httpAuthExtensionConfiguration3();
    resolveRuntimeExtensions3 = (runtimeConfig, extensions) => {
      const extensionConfiguration = Object.assign(getAwsRegionExtensionConfiguration(runtimeConfig), getDefaultExtensionConfiguration(runtimeConfig), getHttpHandlerExtensionConfiguration(runtimeConfig), getHttpAuthExtensionConfiguration3(runtimeConfig));
      extensions.forEach((extension) => extension.configure(extensionConfiguration));
      return Object.assign(runtimeConfig, resolveAwsRegionExtensionConfiguration(extensionConfiguration), resolveDefaultRuntimeConfig(extensionConfiguration), resolveHttpHandlerRuntimeConfig(extensionConfiguration), resolveHttpAuthRuntimeConfig3(extensionConfiguration));
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/STSClient.js
var STSClient;
var init_STSClient = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/STSClient.js"() {
    init_dist_es3();
    init_dist_es4();
    init_dist_es5();
    init_dist_es30();
    init_dist_es32();
    init_dist_es19();
    init_schema2();
    init_dist_es33();
    init_dist_es36();
    init_dist_es39();
    init_dist_es27();
    init_httpAuthSchemeProvider3();
    init_EndpointParameters3();
    init_runtimeConfig3();
    init_runtimeExtensions3();
    STSClient = class extends Client {
      config;
      constructor(...[configuration]) {
        const _config_0 = getRuntimeConfig6(configuration || {});
        super(_config_0);
        this.initConfig = _config_0;
        const _config_1 = resolveClientEndpointParameters4(_config_0);
        const _config_2 = resolveUserAgentConfig(_config_1);
        const _config_3 = resolveRetryConfig(_config_2);
        const _config_4 = resolveRegionConfig(_config_3);
        const _config_5 = resolveHostHeaderConfig(_config_4);
        const _config_6 = resolveEndpointConfig(_config_5);
        const _config_7 = resolveHttpAuthSchemeConfig4(_config_6);
        const _config_8 = resolveRuntimeExtensions3(_config_7, configuration?.extensions || []);
        this.config = _config_8;
        this.middlewareStack.use(getSchemaSerdePlugin(this.config));
        this.middlewareStack.use(getUserAgentPlugin(this.config));
        this.middlewareStack.use(getRetryPlugin(this.config));
        this.middlewareStack.use(getContentLengthPlugin(this.config));
        this.middlewareStack.use(getHostHeaderPlugin(this.config));
        this.middlewareStack.use(getLoggerPlugin(this.config));
        this.middlewareStack.use(getRecursionDetectionPlugin(this.config));
        this.middlewareStack.use(getHttpAuthSchemeEndpointRuleSetPlugin(this.config, {
          httpAuthSchemeParametersProvider: defaultSTSHttpAuthSchemeParametersProvider,
          identityProviderConfigProvider: async (config) => new DefaultIdentityProviderConfig({
            "aws.auth#sigv4": config.credentials
          })
        }));
        this.middlewareStack.use(getHttpSigningPlugin(this.config));
      }
      destroy() {
        super.destroy();
      }
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/models/STSServiceException.js
var STSServiceException;
var init_STSServiceException = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/models/STSServiceException.js"() {
    init_dist_es27();
    STSServiceException = class _STSServiceException extends ServiceException {
      constructor(options) {
        super(options);
        Object.setPrototypeOf(this, _STSServiceException.prototype);
      }
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/models/errors.js
var ExpiredTokenException2, MalformedPolicyDocumentException, PackedPolicyTooLargeException, RegionDisabledException, IDPRejectedClaimException, InvalidIdentityTokenException, IDPCommunicationErrorException;
var init_errors3 = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/models/errors.js"() {
    init_STSServiceException();
    ExpiredTokenException2 = class _ExpiredTokenException extends STSServiceException {
      name = "ExpiredTokenException";
      $fault = "client";
      constructor(opts) {
        super({
          name: "ExpiredTokenException",
          $fault: "client",
          ...opts
        });
        Object.setPrototypeOf(this, _ExpiredTokenException.prototype);
      }
    };
    MalformedPolicyDocumentException = class _MalformedPolicyDocumentException extends STSServiceException {
      name = "MalformedPolicyDocumentException";
      $fault = "client";
      constructor(opts) {
        super({
          name: "MalformedPolicyDocumentException",
          $fault: "client",
          ...opts
        });
        Object.setPrototypeOf(this, _MalformedPolicyDocumentException.prototype);
      }
    };
    PackedPolicyTooLargeException = class _PackedPolicyTooLargeException extends STSServiceException {
      name = "PackedPolicyTooLargeException";
      $fault = "client";
      constructor(opts) {
        super({
          name: "PackedPolicyTooLargeException",
          $fault: "client",
          ...opts
        });
        Object.setPrototypeOf(this, _PackedPolicyTooLargeException.prototype);
      }
    };
    RegionDisabledException = class _RegionDisabledException extends STSServiceException {
      name = "RegionDisabledException";
      $fault = "client";
      constructor(opts) {
        super({
          name: "RegionDisabledException",
          $fault: "client",
          ...opts
        });
        Object.setPrototypeOf(this, _RegionDisabledException.prototype);
      }
    };
    IDPRejectedClaimException = class _IDPRejectedClaimException extends STSServiceException {
      name = "IDPRejectedClaimException";
      $fault = "client";
      constructor(opts) {
        super({
          name: "IDPRejectedClaimException",
          $fault: "client",
          ...opts
        });
        Object.setPrototypeOf(this, _IDPRejectedClaimException.prototype);
      }
    };
    InvalidIdentityTokenException = class _InvalidIdentityTokenException extends STSServiceException {
      name = "InvalidIdentityTokenException";
      $fault = "client";
      constructor(opts) {
        super({
          name: "InvalidIdentityTokenException",
          $fault: "client",
          ...opts
        });
        Object.setPrototypeOf(this, _InvalidIdentityTokenException.prototype);
      }
    };
    IDPCommunicationErrorException = class _IDPCommunicationErrorException extends STSServiceException {
      name = "IDPCommunicationErrorException";
      $fault = "client";
      constructor(opts) {
        super({
          name: "IDPCommunicationErrorException",
          $fault: "client",
          ...opts
        });
        Object.setPrototypeOf(this, _IDPCommunicationErrorException.prototype);
      }
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/schemas/schemas_0.js
var _A, _AKI, _AR, _ARI, _ARR, _ARRs, _ARU, _ARWWI, _ARWWIR, _ARWWIRs, _Au, _C, _CA, _DS, _E, _EI, _ETE2, _IDPCEE, _IDPRCE, _IITE, _K, _MPDE, _P, _PA, _PAr, _PC, _PCLT, _PCr, _PDT, _PI, _PPS, _PPTLE, _Pr, _RA, _RDE, _RSN, _SAK, _SFWIT, _SI, _SN, _ST, _T, _TC, _TTK, _Ta, _V, _WIT, _a, _aKST, _aQE, _c3, _cTT, _e3, _hE3, _m2, _pDLT, _s3, _tLT, n03, accessKeySecretType, clientTokenType, AssumedRoleUser$, AssumeRoleRequest$, AssumeRoleResponse$, AssumeRoleWithWebIdentityRequest$, AssumeRoleWithWebIdentityResponse$, Credentials$, ExpiredTokenException$2, IDPCommunicationErrorException$, IDPRejectedClaimException$, InvalidIdentityTokenException$, MalformedPolicyDocumentException$, PackedPolicyTooLargeException$, PolicyDescriptorType$, ProvidedContext$, RegionDisabledException$, Tag$, STSServiceException$, policyDescriptorListType, ProvidedContextsListType, tagKeyListType, tagListType, AssumeRole$, AssumeRoleWithWebIdentity$;
var init_schemas_03 = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/schemas/schemas_0.js"() {
    init_schema2();
    init_errors3();
    init_STSServiceException();
    _A = "Arn";
    _AKI = "AccessKeyId";
    _AR = "AssumeRole";
    _ARI = "AssumedRoleId";
    _ARR = "AssumeRoleRequest";
    _ARRs = "AssumeRoleResponse";
    _ARU = "AssumedRoleUser";
    _ARWWI = "AssumeRoleWithWebIdentity";
    _ARWWIR = "AssumeRoleWithWebIdentityRequest";
    _ARWWIRs = "AssumeRoleWithWebIdentityResponse";
    _Au = "Audience";
    _C = "Credentials";
    _CA = "ContextAssertion";
    _DS = "DurationSeconds";
    _E = "Expiration";
    _EI = "ExternalId";
    _ETE2 = "ExpiredTokenException";
    _IDPCEE = "IDPCommunicationErrorException";
    _IDPRCE = "IDPRejectedClaimException";
    _IITE = "InvalidIdentityTokenException";
    _K = "Key";
    _MPDE = "MalformedPolicyDocumentException";
    _P = "Policy";
    _PA = "PolicyArns";
    _PAr = "ProviderArn";
    _PC = "ProvidedContexts";
    _PCLT = "ProvidedContextsListType";
    _PCr = "ProvidedContext";
    _PDT = "PolicyDescriptorType";
    _PI = "ProviderId";
    _PPS = "PackedPolicySize";
    _PPTLE = "PackedPolicyTooLargeException";
    _Pr = "Provider";
    _RA = "RoleArn";
    _RDE = "RegionDisabledException";
    _RSN = "RoleSessionName";
    _SAK = "SecretAccessKey";
    _SFWIT = "SubjectFromWebIdentityToken";
    _SI = "SourceIdentity";
    _SN = "SerialNumber";
    _ST = "SessionToken";
    _T = "Tags";
    _TC = "TokenCode";
    _TTK = "TransitiveTagKeys";
    _Ta = "Tag";
    _V = "Value";
    _WIT = "WebIdentityToken";
    _a = "arn";
    _aKST = "accessKeySecretType";
    _aQE = "awsQueryError";
    _c3 = "client";
    _cTT = "clientTokenType";
    _e3 = "error";
    _hE3 = "httpError";
    _m2 = "message";
    _pDLT = "policyDescriptorListType";
    _s3 = "smithy.ts.sdk.synthetic.com.amazonaws.sts";
    _tLT = "tagListType";
    n03 = "com.amazonaws.sts";
    accessKeySecretType = [0, n03, _aKST, 8, 0];
    clientTokenType = [0, n03, _cTT, 8, 0];
    AssumedRoleUser$ = [3, n03, _ARU, 0, [_ARI, _A], [0, 0]];
    AssumeRoleRequest$ = [
      3,
      n03,
      _ARR,
      0,
      [_RA, _RSN, _PA, _P, _DS, _T, _TTK, _EI, _SN, _TC, _SI, _PC],
      [0, 0, () => policyDescriptorListType, 0, 1, () => tagListType, 64 | 0, 0, 0, 0, 0, () => ProvidedContextsListType]
    ];
    AssumeRoleResponse$ = [
      3,
      n03,
      _ARRs,
      0,
      [_C, _ARU, _PPS, _SI],
      [[() => Credentials$, 0], () => AssumedRoleUser$, 1, 0]
    ];
    AssumeRoleWithWebIdentityRequest$ = [
      3,
      n03,
      _ARWWIR,
      0,
      [_RA, _RSN, _WIT, _PI, _PA, _P, _DS],
      [0, 0, [() => clientTokenType, 0], 0, () => policyDescriptorListType, 0, 1]
    ];
    AssumeRoleWithWebIdentityResponse$ = [
      3,
      n03,
      _ARWWIRs,
      0,
      [_C, _SFWIT, _ARU, _PPS, _Pr, _Au, _SI],
      [[() => Credentials$, 0], 0, () => AssumedRoleUser$, 1, 0, 0, 0]
    ];
    Credentials$ = [
      3,
      n03,
      _C,
      0,
      [_AKI, _SAK, _ST, _E],
      [0, [() => accessKeySecretType, 0], 0, 4]
    ];
    ExpiredTokenException$2 = [
      -3,
      n03,
      _ETE2,
      { [_aQE]: [`ExpiredTokenException`, 400], [_e3]: _c3, [_hE3]: 400 },
      [_m2],
      [0]
    ];
    TypeRegistry.for(n03).registerError(ExpiredTokenException$2, ExpiredTokenException2);
    IDPCommunicationErrorException$ = [
      -3,
      n03,
      _IDPCEE,
      { [_aQE]: [`IDPCommunicationError`, 400], [_e3]: _c3, [_hE3]: 400 },
      [_m2],
      [0]
    ];
    TypeRegistry.for(n03).registerError(IDPCommunicationErrorException$, IDPCommunicationErrorException);
    IDPRejectedClaimException$ = [
      -3,
      n03,
      _IDPRCE,
      { [_aQE]: [`IDPRejectedClaim`, 403], [_e3]: _c3, [_hE3]: 403 },
      [_m2],
      [0]
    ];
    TypeRegistry.for(n03).registerError(IDPRejectedClaimException$, IDPRejectedClaimException);
    InvalidIdentityTokenException$ = [
      -3,
      n03,
      _IITE,
      { [_aQE]: [`InvalidIdentityToken`, 400], [_e3]: _c3, [_hE3]: 400 },
      [_m2],
      [0]
    ];
    TypeRegistry.for(n03).registerError(InvalidIdentityTokenException$, InvalidIdentityTokenException);
    MalformedPolicyDocumentException$ = [
      -3,
      n03,
      _MPDE,
      { [_aQE]: [`MalformedPolicyDocument`, 400], [_e3]: _c3, [_hE3]: 400 },
      [_m2],
      [0]
    ];
    TypeRegistry.for(n03).registerError(MalformedPolicyDocumentException$, MalformedPolicyDocumentException);
    PackedPolicyTooLargeException$ = [
      -3,
      n03,
      _PPTLE,
      { [_aQE]: [`PackedPolicyTooLarge`, 400], [_e3]: _c3, [_hE3]: 400 },
      [_m2],
      [0]
    ];
    TypeRegistry.for(n03).registerError(PackedPolicyTooLargeException$, PackedPolicyTooLargeException);
    PolicyDescriptorType$ = [3, n03, _PDT, 0, [_a], [0]];
    ProvidedContext$ = [3, n03, _PCr, 0, [_PAr, _CA], [0, 0]];
    RegionDisabledException$ = [
      -3,
      n03,
      _RDE,
      { [_aQE]: [`RegionDisabledException`, 403], [_e3]: _c3, [_hE3]: 403 },
      [_m2],
      [0]
    ];
    TypeRegistry.for(n03).registerError(RegionDisabledException$, RegionDisabledException);
    Tag$ = [3, n03, _Ta, 0, [_K, _V], [0, 0]];
    STSServiceException$ = [-3, _s3, "STSServiceException", 0, [], []];
    TypeRegistry.for(_s3).registerError(STSServiceException$, STSServiceException);
    policyDescriptorListType = [1, n03, _pDLT, 0, () => PolicyDescriptorType$];
    ProvidedContextsListType = [1, n03, _PCLT, 0, () => ProvidedContext$];
    tagKeyListType = 64 | 0;
    tagListType = [1, n03, _tLT, 0, () => Tag$];
    AssumeRole$ = [9, n03, _AR, 0, () => AssumeRoleRequest$, () => AssumeRoleResponse$];
    AssumeRoleWithWebIdentity$ = [
      9,
      n03,
      _ARWWI,
      0,
      () => AssumeRoleWithWebIdentityRequest$,
      () => AssumeRoleWithWebIdentityResponse$
    ];
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/commands/AssumeRoleCommand.js
var AssumeRoleCommand;
var init_AssumeRoleCommand = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/commands/AssumeRoleCommand.js"() {
    init_dist_es36();
    init_dist_es27();
    init_EndpointParameters3();
    init_schemas_03();
    AssumeRoleCommand = class extends Command.classBuilder().ep(commonParams4).m(function(Command2, cs, config, o6) {
      return [getEndpointPlugin(config, Command2.getEndpointParameterInstructions())];
    }).s("AWSSecurityTokenServiceV20110615", "AssumeRole", {}).n("STSClient", "AssumeRoleCommand").sc(AssumeRole$).build() {
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/commands/AssumeRoleWithWebIdentityCommand.js
var AssumeRoleWithWebIdentityCommand;
var init_AssumeRoleWithWebIdentityCommand = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/commands/AssumeRoleWithWebIdentityCommand.js"() {
    init_dist_es36();
    init_dist_es27();
    init_EndpointParameters3();
    init_schemas_03();
    AssumeRoleWithWebIdentityCommand = class extends Command.classBuilder().ep(commonParams4).m(function(Command2, cs, config, o6) {
      return [getEndpointPlugin(config, Command2.getEndpointParameterInstructions())];
    }).s("AWSSecurityTokenServiceV20110615", "AssumeRoleWithWebIdentity", {}).n("STSClient", "AssumeRoleWithWebIdentityCommand").sc(AssumeRoleWithWebIdentity$).build() {
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/STS.js
var commands3, STS;
var init_STS = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/STS.js"() {
    init_dist_es27();
    init_AssumeRoleCommand();
    init_AssumeRoleWithWebIdentityCommand();
    init_STSClient();
    commands3 = {
      AssumeRoleCommand,
      AssumeRoleWithWebIdentityCommand
    };
    STS = class extends STSClient {
    };
    createAggregatedClient(commands3, STS);
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/commands/index.js
var init_commands3 = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/commands/index.js"() {
    init_AssumeRoleCommand();
    init_AssumeRoleWithWebIdentityCommand();
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/models/models_0.js
var init_models_03 = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/models/models_0.js"() {
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/defaultStsRoleAssumers.js
var getAccountIdFromAssumedRoleUser, resolveRegion, getDefaultRoleAssumer, getDefaultRoleAssumerWithWebIdentity, isH2;
var init_defaultStsRoleAssumers = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/defaultStsRoleAssumers.js"() {
    init_client2();
    init_dist_es47();
    init_AssumeRoleCommand();
    init_AssumeRoleWithWebIdentityCommand();
    getAccountIdFromAssumedRoleUser = (assumedRoleUser) => {
      if (typeof assumedRoleUser?.Arn === "string") {
        const arnComponents = assumedRoleUser.Arn.split(":");
        if (arnComponents.length > 4 && arnComponents[4] !== "") {
          return arnComponents[4];
        }
      }
      return void 0;
    };
    resolveRegion = async (_region, _parentRegion, credentialProviderLogger, loaderConfig = {}) => {
      const region = typeof _region === "function" ? await _region() : _region;
      const parentRegion = typeof _parentRegion === "function" ? await _parentRegion() : _parentRegion;
      let stsDefaultRegion = "";
      const resolvedRegion = region ?? parentRegion ?? (stsDefaultRegion = await stsRegionDefaultResolver(loaderConfig)());
      credentialProviderLogger?.debug?.("@aws-sdk/client-sts::resolveRegion", "accepting first of:", `${region} (credential provider clientConfig)`, `${parentRegion} (contextual client)`, `${stsDefaultRegion} (STS default: AWS_REGION, profile region, or us-east-1)`);
      return resolvedRegion;
    };
    getDefaultRoleAssumer = (stsOptions, STSClient2) => {
      let stsClient;
      let closureSourceCreds;
      return async (sourceCreds, params) => {
        closureSourceCreds = sourceCreds;
        if (!stsClient) {
          const { logger: logger2 = stsOptions?.parentClientConfig?.logger, profile = stsOptions?.parentClientConfig?.profile, region, requestHandler = stsOptions?.parentClientConfig?.requestHandler, credentialProviderLogger, userAgentAppId = stsOptions?.parentClientConfig?.userAgentAppId } = stsOptions;
          const resolvedRegion = await resolveRegion(region, stsOptions?.parentClientConfig?.region, credentialProviderLogger, {
            logger: logger2,
            profile
          });
          const isCompatibleRequestHandler = !isH2(requestHandler);
          stsClient = new STSClient2({
            ...stsOptions,
            userAgentAppId,
            profile,
            credentialDefaultProvider: () => async () => closureSourceCreds,
            region: resolvedRegion,
            requestHandler: isCompatibleRequestHandler ? requestHandler : void 0,
            logger: logger2
          });
        }
        const { Credentials, AssumedRoleUser } = await stsClient.send(new AssumeRoleCommand(params));
        if (!Credentials || !Credentials.AccessKeyId || !Credentials.SecretAccessKey) {
          throw new Error(`Invalid response from STS.assumeRole call with role ${params.RoleArn}`);
        }
        const accountId = getAccountIdFromAssumedRoleUser(AssumedRoleUser);
        const credentials = {
          accessKeyId: Credentials.AccessKeyId,
          secretAccessKey: Credentials.SecretAccessKey,
          sessionToken: Credentials.SessionToken,
          expiration: Credentials.Expiration,
          ...Credentials.CredentialScope && { credentialScope: Credentials.CredentialScope },
          ...accountId && { accountId }
        };
        setCredentialFeature(credentials, "CREDENTIALS_STS_ASSUME_ROLE", "i");
        return credentials;
      };
    };
    getDefaultRoleAssumerWithWebIdentity = (stsOptions, STSClient2) => {
      let stsClient;
      return async (params) => {
        if (!stsClient) {
          const { logger: logger2 = stsOptions?.parentClientConfig?.logger, profile = stsOptions?.parentClientConfig?.profile, region, requestHandler = stsOptions?.parentClientConfig?.requestHandler, credentialProviderLogger, userAgentAppId = stsOptions?.parentClientConfig?.userAgentAppId } = stsOptions;
          const resolvedRegion = await resolveRegion(region, stsOptions?.parentClientConfig?.region, credentialProviderLogger, {
            logger: logger2,
            profile
          });
          const isCompatibleRequestHandler = !isH2(requestHandler);
          stsClient = new STSClient2({
            ...stsOptions,
            userAgentAppId,
            profile,
            region: resolvedRegion,
            requestHandler: isCompatibleRequestHandler ? requestHandler : void 0,
            logger: logger2
          });
        }
        const { Credentials, AssumedRoleUser } = await stsClient.send(new AssumeRoleWithWebIdentityCommand(params));
        if (!Credentials || !Credentials.AccessKeyId || !Credentials.SecretAccessKey) {
          throw new Error(`Invalid response from STS.assumeRoleWithWebIdentity call with role ${params.RoleArn}`);
        }
        const accountId = getAccountIdFromAssumedRoleUser(AssumedRoleUser);
        const credentials = {
          accessKeyId: Credentials.AccessKeyId,
          secretAccessKey: Credentials.SecretAccessKey,
          sessionToken: Credentials.SessionToken,
          expiration: Credentials.Expiration,
          ...Credentials.CredentialScope && { credentialScope: Credentials.CredentialScope },
          ...accountId && { accountId }
        };
        if (accountId) {
          setCredentialFeature(credentials, "RESOLVED_ACCOUNT_ID", "T");
        }
        setCredentialFeature(credentials, "CREDENTIALS_STS_ASSUME_ROLE_WEB_ID", "k");
        return credentials;
      };
    };
    isH2 = (requestHandler) => {
      return requestHandler?.metadata?.handlerProtocol === "h2";
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/defaultRoleAssumers.js
var getCustomizableStsClientCtor, getDefaultRoleAssumer2, getDefaultRoleAssumerWithWebIdentity2, decorateDefaultCredentialProvider;
var init_defaultRoleAssumers = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/defaultRoleAssumers.js"() {
    init_defaultStsRoleAssumers();
    init_STSClient();
    getCustomizableStsClientCtor = (baseCtor, customizations) => {
      if (!customizations)
        return baseCtor;
      else
        return class CustomizableSTSClient extends baseCtor {
          constructor(config) {
            super(config);
            for (const customization of customizations) {
              this.middlewareStack.use(customization);
            }
          }
        };
    };
    getDefaultRoleAssumer2 = (stsOptions = {}, stsPlugins) => getDefaultRoleAssumer(stsOptions, getCustomizableStsClientCtor(STSClient, stsPlugins));
    getDefaultRoleAssumerWithWebIdentity2 = (stsOptions = {}, stsPlugins) => getDefaultRoleAssumerWithWebIdentity(stsOptions, getCustomizableStsClientCtor(STSClient, stsPlugins));
    decorateDefaultCredentialProvider = (provider) => (input) => provider({
      roleAssumer: getDefaultRoleAssumer2(input),
      roleAssumerWithWebIdentity: getDefaultRoleAssumerWithWebIdentity2(input),
      ...input
    });
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/index.js
var sts_exports = {};
__export(sts_exports, {
  $Command: () => Command,
  AssumeRole$: () => AssumeRole$,
  AssumeRoleCommand: () => AssumeRoleCommand,
  AssumeRoleRequest$: () => AssumeRoleRequest$,
  AssumeRoleResponse$: () => AssumeRoleResponse$,
  AssumeRoleWithWebIdentity$: () => AssumeRoleWithWebIdentity$,
  AssumeRoleWithWebIdentityCommand: () => AssumeRoleWithWebIdentityCommand,
  AssumeRoleWithWebIdentityRequest$: () => AssumeRoleWithWebIdentityRequest$,
  AssumeRoleWithWebIdentityResponse$: () => AssumeRoleWithWebIdentityResponse$,
  AssumedRoleUser$: () => AssumedRoleUser$,
  Credentials$: () => Credentials$,
  ExpiredTokenException: () => ExpiredTokenException2,
  ExpiredTokenException$: () => ExpiredTokenException$2,
  IDPCommunicationErrorException: () => IDPCommunicationErrorException,
  IDPCommunicationErrorException$: () => IDPCommunicationErrorException$,
  IDPRejectedClaimException: () => IDPRejectedClaimException,
  IDPRejectedClaimException$: () => IDPRejectedClaimException$,
  InvalidIdentityTokenException: () => InvalidIdentityTokenException,
  InvalidIdentityTokenException$: () => InvalidIdentityTokenException$,
  MalformedPolicyDocumentException: () => MalformedPolicyDocumentException,
  MalformedPolicyDocumentException$: () => MalformedPolicyDocumentException$,
  PackedPolicyTooLargeException: () => PackedPolicyTooLargeException,
  PackedPolicyTooLargeException$: () => PackedPolicyTooLargeException$,
  PolicyDescriptorType$: () => PolicyDescriptorType$,
  ProvidedContext$: () => ProvidedContext$,
  RegionDisabledException: () => RegionDisabledException,
  RegionDisabledException$: () => RegionDisabledException$,
  STS: () => STS,
  STSClient: () => STSClient,
  STSServiceException: () => STSServiceException,
  STSServiceException$: () => STSServiceException$,
  Tag$: () => Tag$,
  __Client: () => Client,
  decorateDefaultCredentialProvider: () => decorateDefaultCredentialProvider,
  getDefaultRoleAssumer: () => getDefaultRoleAssumer2,
  getDefaultRoleAssumerWithWebIdentity: () => getDefaultRoleAssumerWithWebIdentity2
});
var init_sts = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/sts/index.js"() {
    init_STSClient();
    init_STS();
    init_commands3();
    init_schemas_03();
    init_errors3();
    init_models_03();
    init_defaultRoleAssumers();
    init_STSServiceException();
  }
});

// node_modules/@aws-sdk/credential-provider-ini/dist-es/resolveAssumeRoleCredentials.js
var isAssumeRoleProfile, isAssumeRoleWithSourceProfile, isCredentialSourceProfile, resolveAssumeRoleCredentials, isCredentialSourceWithoutRoleArn;
var init_resolveAssumeRoleCredentials = __esm({
  "node_modules/@aws-sdk/credential-provider-ini/dist-es/resolveAssumeRoleCredentials.js"() {
    init_client2();
    init_dist_es24();
    init_dist_es34();
    init_resolveCredentialSource();
    isAssumeRoleProfile = (arg, { profile = "default", logger: logger2 } = {}) => {
      return Boolean(arg) && typeof arg === "object" && typeof arg.role_arn === "string" && ["undefined", "string"].indexOf(typeof arg.role_session_name) > -1 && ["undefined", "string"].indexOf(typeof arg.external_id) > -1 && ["undefined", "string"].indexOf(typeof arg.mfa_serial) > -1 && (isAssumeRoleWithSourceProfile(arg, { profile, logger: logger2 }) || isCredentialSourceProfile(arg, { profile, logger: logger2 }));
    };
    isAssumeRoleWithSourceProfile = (arg, { profile, logger: logger2 }) => {
      const withSourceProfile = typeof arg.source_profile === "string" && typeof arg.credential_source === "undefined";
      if (withSourceProfile) {
        logger2?.debug?.(`    ${profile} isAssumeRoleWithSourceProfile source_profile=${arg.source_profile}`);
      }
      return withSourceProfile;
    };
    isCredentialSourceProfile = (arg, { profile, logger: logger2 }) => {
      const withProviderProfile = typeof arg.credential_source === "string" && typeof arg.source_profile === "undefined";
      if (withProviderProfile) {
        logger2?.debug?.(`    ${profile} isCredentialSourceProfile credential_source=${arg.credential_source}`);
      }
      return withProviderProfile;
    };
    resolveAssumeRoleCredentials = async (profileName, profiles, options, callerClientConfig, visitedProfiles = {}, resolveProfileData2) => {
      options.logger?.debug("@aws-sdk/credential-provider-ini - resolveAssumeRoleCredentials (STS)");
      const profileData = profiles[profileName];
      const { source_profile, region } = profileData;
      if (!options.roleAssumer) {
        const { getDefaultRoleAssumer: getDefaultRoleAssumer3 } = await Promise.resolve().then(() => (init_sts(), sts_exports));
        options.roleAssumer = getDefaultRoleAssumer3({
          ...options.clientConfig,
          credentialProviderLogger: options.logger,
          parentClientConfig: {
            ...callerClientConfig,
            ...options?.parentClientConfig,
            region: region ?? options?.parentClientConfig?.region ?? callerClientConfig?.region
          }
        }, options.clientPlugins);
      }
      if (source_profile && source_profile in visitedProfiles) {
        throw new CredentialsProviderError(`Detected a cycle attempting to resolve credentials for profile ${getProfileName(options)}. Profiles visited: ` + Object.keys(visitedProfiles).join(", "), { logger: options.logger });
      }
      options.logger?.debug(`@aws-sdk/credential-provider-ini - finding credential resolver using ${source_profile ? `source_profile=[${source_profile}]` : `profile=[${profileName}]`}`);
      const sourceCredsProvider = source_profile ? resolveProfileData2(source_profile, profiles, options, callerClientConfig, {
        ...visitedProfiles,
        [source_profile]: true
      }, isCredentialSourceWithoutRoleArn(profiles[source_profile] ?? {})) : (await resolveCredentialSource(profileData.credential_source, profileName, options.logger)(options))();
      if (isCredentialSourceWithoutRoleArn(profileData)) {
        return sourceCredsProvider.then((creds) => setCredentialFeature(creds, "CREDENTIALS_PROFILE_SOURCE_PROFILE", "o"));
      } else {
        const params = {
          RoleArn: profileData.role_arn,
          RoleSessionName: profileData.role_session_name || `aws-sdk-js-${Date.now()}`,
          ExternalId: profileData.external_id,
          DurationSeconds: parseInt(profileData.duration_seconds || "3600", 10)
        };
        const { mfa_serial } = profileData;
        if (mfa_serial) {
          if (!options.mfaCodeProvider) {
            throw new CredentialsProviderError(`Profile ${profileName} requires multi-factor authentication, but no MFA code callback was provided.`, { logger: options.logger, tryNextLink: false });
          }
          params.SerialNumber = mfa_serial;
          params.TokenCode = await options.mfaCodeProvider(mfa_serial);
        }
        const sourceCreds = await sourceCredsProvider;
        return options.roleAssumer(sourceCreds, params).then((creds) => setCredentialFeature(creds, "CREDENTIALS_PROFILE_SOURCE_PROFILE", "o"));
      }
    };
    isCredentialSourceWithoutRoleArn = (section) => {
      return !section.role_arn && !!section.credential_source;
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/auth/httpAuthSchemeProvider.js
function createAwsAuthSigv4HttpAuthOption5(authParameters) {
  return {
    schemeId: "aws.auth#sigv4",
    signingProperties: {
      name: "signin",
      region: authParameters.region
    },
    propertiesExtractor: (config, context) => ({
      signingProperties: {
        config,
        context
      }
    })
  };
}
function createSmithyApiNoAuthHttpAuthOption4(authParameters) {
  return {
    schemeId: "smithy.api#noAuth"
  };
}
var defaultSigninHttpAuthSchemeParametersProvider, defaultSigninHttpAuthSchemeProvider, resolveHttpAuthSchemeConfig5;
var init_httpAuthSchemeProvider4 = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/auth/httpAuthSchemeProvider.js"() {
    init_dist_es29();
    init_dist_es6();
    defaultSigninHttpAuthSchemeParametersProvider = async (config, context, input) => {
      return {
        operation: getSmithyContext(context).operation,
        region: await normalizeProvider(config.region)() || (() => {
          throw new Error("expected `region` to be configured for `aws.auth#sigv4`");
        })()
      };
    };
    defaultSigninHttpAuthSchemeProvider = (authParameters) => {
      const options = [];
      switch (authParameters.operation) {
        case "CreateOAuth2Token": {
          options.push(createSmithyApiNoAuthHttpAuthOption4(authParameters));
          break;
        }
        default: {
          options.push(createAwsAuthSigv4HttpAuthOption5(authParameters));
        }
      }
      return options;
    };
    resolveHttpAuthSchemeConfig5 = (config) => {
      const config_0 = resolveAwsSdkSigV4Config(config);
      return Object.assign(config_0, {
        authSchemePreference: normalizeProvider(config.authSchemePreference ?? [])
      });
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/endpoint/EndpointParameters.js
var resolveClientEndpointParameters5, commonParams5;
var init_EndpointParameters4 = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/endpoint/EndpointParameters.js"() {
    resolveClientEndpointParameters5 = (options) => {
      return Object.assign(options, {
        useDualstackEndpoint: options.useDualstackEndpoint ?? false,
        useFipsEndpoint: options.useFipsEndpoint ?? false,
        defaultSigningName: "signin"
      });
    };
    commonParams5 = {
      UseFIPS: { type: "builtInParams", name: "useFipsEndpoint" },
      Endpoint: { type: "builtInParams", name: "endpoint" },
      Region: { type: "builtInParams", name: "region" },
      UseDualStack: { type: "builtInParams", name: "useDualstackEndpoint" }
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/endpoint/ruleset.js
var u4, v5, w4, x4, a4, b4, c4, d4, e4, f4, g4, h4, i4, j4, k4, l4, m4, n4, o4, p4, q4, r4, s4, t4, _data4, ruleSet4;
var init_ruleset4 = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/endpoint/ruleset.js"() {
    u4 = "required";
    v5 = "fn";
    w4 = "argv";
    x4 = "ref";
    a4 = true;
    b4 = "isSet";
    c4 = "booleanEquals";
    d4 = "error";
    e4 = "endpoint";
    f4 = "tree";
    g4 = "PartitionResult";
    h4 = "stringEquals";
    i4 = { [u4]: true, "default": false, "type": "boolean" };
    j4 = { [u4]: false, "type": "string" };
    k4 = { [x4]: "Endpoint" };
    l4 = { [v5]: c4, [w4]: [{ [x4]: "UseFIPS" }, true] };
    m4 = { [v5]: c4, [w4]: [{ [x4]: "UseDualStack" }, true] };
    n4 = {};
    o4 = { [v5]: "getAttr", [w4]: [{ [x4]: g4 }, "name"] };
    p4 = { [v5]: c4, [w4]: [{ [x4]: "UseFIPS" }, false] };
    q4 = { [v5]: c4, [w4]: [{ [x4]: "UseDualStack" }, false] };
    r4 = { [v5]: "getAttr", [w4]: [{ [x4]: g4 }, "supportsFIPS"] };
    s4 = { [v5]: c4, [w4]: [true, { [v5]: "getAttr", [w4]: [{ [x4]: g4 }, "supportsDualStack"] }] };
    t4 = [{ [x4]: "Region" }];
    _data4 = { version: "1.0", parameters: { UseDualStack: i4, UseFIPS: i4, Endpoint: j4, Region: j4 }, rules: [{ conditions: [{ [v5]: b4, [w4]: [k4] }], rules: [{ conditions: [l4], error: "Invalid Configuration: FIPS and custom endpoint are not supported", type: d4 }, { rules: [{ conditions: [m4], error: "Invalid Configuration: Dualstack and custom endpoint are not supported", type: d4 }, { endpoint: { url: k4, properties: n4, headers: n4 }, type: e4 }], type: f4 }], type: f4 }, { rules: [{ conditions: [{ [v5]: b4, [w4]: t4 }], rules: [{ conditions: [{ [v5]: "aws.partition", [w4]: t4, assign: g4 }], rules: [{ conditions: [{ [v5]: h4, [w4]: [o4, "aws"] }, p4, q4], endpoint: { url: "https://{Region}.signin.aws.amazon.com", properties: n4, headers: n4 }, type: e4 }, { conditions: [{ [v5]: h4, [w4]: [o4, "aws-cn"] }, p4, q4], endpoint: { url: "https://{Region}.signin.amazonaws.cn", properties: n4, headers: n4 }, type: e4 }, { conditions: [{ [v5]: h4, [w4]: [o4, "aws-us-gov"] }, p4, q4], endpoint: { url: "https://{Region}.signin.amazonaws-us-gov.com", properties: n4, headers: n4 }, type: e4 }, { conditions: [l4, m4], rules: [{ conditions: [{ [v5]: c4, [w4]: [a4, r4] }, s4], rules: [{ endpoint: { url: "https://signin-fips.{Region}.{PartitionResult#dualStackDnsSuffix}", properties: n4, headers: n4 }, type: e4 }], type: f4 }, { error: "FIPS and DualStack are enabled, but this partition does not support one or both", type: d4 }], type: f4 }, { conditions: [l4, q4], rules: [{ conditions: [{ [v5]: c4, [w4]: [r4, a4] }], rules: [{ endpoint: { url: "https://signin-fips.{Region}.{PartitionResult#dnsSuffix}", properties: n4, headers: n4 }, type: e4 }], type: f4 }, { error: "FIPS is enabled but this partition does not support FIPS", type: d4 }], type: f4 }, { conditions: [p4, m4], rules: [{ conditions: [s4], rules: [{ endpoint: { url: "https://signin.{Region}.{PartitionResult#dualStackDnsSuffix}", properties: n4, headers: n4 }, type: e4 }], type: f4 }, { error: "DualStack is enabled but this partition does not support DualStack", type: d4 }], type: f4 }, { endpoint: { url: "https://signin.{Region}.{PartitionResult#dnsSuffix}", properties: n4, headers: n4 }, type: e4 }], type: f4 }], type: f4 }, { error: "Invalid Configuration: Missing Region", type: d4 }], type: f4 }] };
    ruleSet4 = _data4;
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/endpoint/endpointResolver.js
var cache4, defaultEndpointResolver4;
var init_endpointResolver4 = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/endpoint/endpointResolver.js"() {
    init_dist_es23();
    init_dist_es20();
    init_ruleset4();
    cache4 = new EndpointCache({
      size: 50,
      params: ["Endpoint", "Region", "UseDualStack", "UseFIPS"]
    });
    defaultEndpointResolver4 = (endpointParams, context = {}) => {
      return cache4.get(endpointParams, () => resolveEndpoint(ruleSet4, {
        endpointParams,
        logger: context.logger
      }));
    };
    customEndpointFunctions.aws = awsEndpointFunctions;
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/runtimeConfig.shared.js
var getRuntimeConfig7;
var init_runtimeConfig_shared4 = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/runtimeConfig.shared.js"() {
    init_dist_es29();
    init_protocols2();
    init_dist_es19();
    init_dist_es27();
    init_dist_es22();
    init_dist_es11();
    init_dist_es10();
    init_httpAuthSchemeProvider4();
    init_endpointResolver4();
    getRuntimeConfig7 = (config) => {
      return {
        apiVersion: "2023-01-01",
        base64Decoder: config?.base64Decoder ?? fromBase64,
        base64Encoder: config?.base64Encoder ?? toBase64,
        disableHostPrefix: config?.disableHostPrefix ?? false,
        endpointProvider: config?.endpointProvider ?? defaultEndpointResolver4,
        extensions: config?.extensions ?? [],
        httpAuthSchemeProvider: config?.httpAuthSchemeProvider ?? defaultSigninHttpAuthSchemeProvider,
        httpAuthSchemes: config?.httpAuthSchemes ?? [
          {
            schemeId: "aws.auth#sigv4",
            identityProvider: (ipc) => ipc.getIdentityProvider("aws.auth#sigv4"),
            signer: new AwsSdkSigV4Signer()
          },
          {
            schemeId: "smithy.api#noAuth",
            identityProvider: (ipc) => ipc.getIdentityProvider("smithy.api#noAuth") || (async () => ({})),
            signer: new NoAuthSigner()
          }
        ],
        logger: config?.logger ?? new NoOpLogger(),
        protocol: config?.protocol ?? AwsRestJsonProtocol,
        protocolSettings: config?.protocolSettings ?? {
          defaultNamespace: "com.amazonaws.signin",
          version: "2023-01-01",
          serviceTarget: "Signin"
        },
        serviceId: config?.serviceId ?? "Signin",
        urlParser: config?.urlParser ?? parseUrl,
        utf8Decoder: config?.utf8Decoder ?? fromUtf8,
        utf8Encoder: config?.utf8Encoder ?? toUtf8
      };
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/runtimeConfig.js
var getRuntimeConfig8;
var init_runtimeConfig4 = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/runtimeConfig.js"() {
    init_package();
    init_dist_es29();
    init_dist_es43();
    init_dist_es32();
    init_dist_es44();
    init_dist_es39();
    init_dist_es35();
    init_dist_es14();
    init_dist_es27();
    init_dist_es45();
    init_dist_es46();
    init_dist_es38();
    init_runtimeConfig_shared4();
    getRuntimeConfig8 = (config) => {
      emitWarningIfUnsupportedVersion2(process.version);
      const defaultsMode = resolveDefaultsModeConfig(config);
      const defaultConfigProvider = () => defaultsMode().then(loadConfigsForDefaultMode);
      const clientSharedValues = getRuntimeConfig7(config);
      emitWarningIfUnsupportedVersion(process.version);
      const loaderConfig = {
        profile: config?.profile,
        logger: clientSharedValues.logger
      };
      return {
        ...clientSharedValues,
        ...config,
        runtime: "node",
        defaultsMode,
        authSchemePreference: config?.authSchemePreference ?? loadConfig(NODE_AUTH_SCHEME_PREFERENCE_OPTIONS, loaderConfig),
        bodyLengthChecker: config?.bodyLengthChecker ?? calculateBodyLength,
        defaultUserAgentProvider: config?.defaultUserAgentProvider ?? createDefaultUserAgentProvider({ serviceId: clientSharedValues.serviceId, clientVersion: package_default2.version }),
        maxAttempts: config?.maxAttempts ?? loadConfig(NODE_MAX_ATTEMPT_CONFIG_OPTIONS, config),
        region: config?.region ?? loadConfig(NODE_REGION_CONFIG_OPTIONS, { ...NODE_REGION_CONFIG_FILE_OPTIONS, ...loaderConfig }),
        requestHandler: NodeHttpHandler.create(config?.requestHandler ?? defaultConfigProvider),
        retryMode: config?.retryMode ?? loadConfig({
          ...NODE_RETRY_MODE_CONFIG_OPTIONS,
          default: async () => (await defaultConfigProvider()).retryMode || DEFAULT_RETRY_MODE
        }, config),
        sha256: config?.sha256 ?? Hash.bind(null, "sha256"),
        streamCollector: config?.streamCollector ?? streamCollector,
        useDualstackEndpoint: config?.useDualstackEndpoint ?? loadConfig(NODE_USE_DUALSTACK_ENDPOINT_CONFIG_OPTIONS, loaderConfig),
        useFipsEndpoint: config?.useFipsEndpoint ?? loadConfig(NODE_USE_FIPS_ENDPOINT_CONFIG_OPTIONS, loaderConfig),
        userAgentAppId: config?.userAgentAppId ?? loadConfig(NODE_APP_ID_CONFIG_OPTIONS, loaderConfig)
      };
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/auth/httpAuthExtensionConfiguration.js
var getHttpAuthExtensionConfiguration4, resolveHttpAuthRuntimeConfig4;
var init_httpAuthExtensionConfiguration4 = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/auth/httpAuthExtensionConfiguration.js"() {
    getHttpAuthExtensionConfiguration4 = (runtimeConfig) => {
      const _httpAuthSchemes = runtimeConfig.httpAuthSchemes;
      let _httpAuthSchemeProvider = runtimeConfig.httpAuthSchemeProvider;
      let _credentials = runtimeConfig.credentials;
      return {
        setHttpAuthScheme(httpAuthScheme) {
          const index = _httpAuthSchemes.findIndex((scheme) => scheme.schemeId === httpAuthScheme.schemeId);
          if (index === -1) {
            _httpAuthSchemes.push(httpAuthScheme);
          } else {
            _httpAuthSchemes.splice(index, 1, httpAuthScheme);
          }
        },
        httpAuthSchemes() {
          return _httpAuthSchemes;
        },
        setHttpAuthSchemeProvider(httpAuthSchemeProvider) {
          _httpAuthSchemeProvider = httpAuthSchemeProvider;
        },
        httpAuthSchemeProvider() {
          return _httpAuthSchemeProvider;
        },
        setCredentials(credentials) {
          _credentials = credentials;
        },
        credentials() {
          return _credentials;
        }
      };
    };
    resolveHttpAuthRuntimeConfig4 = (config) => {
      return {
        httpAuthSchemes: config.httpAuthSchemes(),
        httpAuthSchemeProvider: config.httpAuthSchemeProvider(),
        credentials: config.credentials()
      };
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/runtimeExtensions.js
var resolveRuntimeExtensions4;
var init_runtimeExtensions4 = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/runtimeExtensions.js"() {
    init_dist_es47();
    init_dist_es2();
    init_dist_es27();
    init_httpAuthExtensionConfiguration4();
    resolveRuntimeExtensions4 = (runtimeConfig, extensions) => {
      const extensionConfiguration = Object.assign(getAwsRegionExtensionConfiguration(runtimeConfig), getDefaultExtensionConfiguration(runtimeConfig), getHttpHandlerExtensionConfiguration(runtimeConfig), getHttpAuthExtensionConfiguration4(runtimeConfig));
      extensions.forEach((extension) => extension.configure(extensionConfiguration));
      return Object.assign(runtimeConfig, resolveAwsRegionExtensionConfiguration(extensionConfiguration), resolveDefaultRuntimeConfig(extensionConfiguration), resolveHttpHandlerRuntimeConfig(extensionConfiguration), resolveHttpAuthRuntimeConfig4(extensionConfiguration));
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/SigninClient.js
var SigninClient;
var init_SigninClient = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/SigninClient.js"() {
    init_dist_es3();
    init_dist_es4();
    init_dist_es5();
    init_dist_es30();
    init_dist_es32();
    init_dist_es19();
    init_schema2();
    init_dist_es33();
    init_dist_es36();
    init_dist_es39();
    init_dist_es27();
    init_httpAuthSchemeProvider4();
    init_EndpointParameters4();
    init_runtimeConfig4();
    init_runtimeExtensions4();
    SigninClient = class extends Client {
      config;
      constructor(...[configuration]) {
        const _config_0 = getRuntimeConfig8(configuration || {});
        super(_config_0);
        this.initConfig = _config_0;
        const _config_1 = resolveClientEndpointParameters5(_config_0);
        const _config_2 = resolveUserAgentConfig(_config_1);
        const _config_3 = resolveRetryConfig(_config_2);
        const _config_4 = resolveRegionConfig(_config_3);
        const _config_5 = resolveHostHeaderConfig(_config_4);
        const _config_6 = resolveEndpointConfig(_config_5);
        const _config_7 = resolveHttpAuthSchemeConfig5(_config_6);
        const _config_8 = resolveRuntimeExtensions4(_config_7, configuration?.extensions || []);
        this.config = _config_8;
        this.middlewareStack.use(getSchemaSerdePlugin(this.config));
        this.middlewareStack.use(getUserAgentPlugin(this.config));
        this.middlewareStack.use(getRetryPlugin(this.config));
        this.middlewareStack.use(getContentLengthPlugin(this.config));
        this.middlewareStack.use(getHostHeaderPlugin(this.config));
        this.middlewareStack.use(getLoggerPlugin(this.config));
        this.middlewareStack.use(getRecursionDetectionPlugin(this.config));
        this.middlewareStack.use(getHttpAuthSchemeEndpointRuleSetPlugin(this.config, {
          httpAuthSchemeParametersProvider: defaultSigninHttpAuthSchemeParametersProvider,
          identityProviderConfigProvider: async (config) => new DefaultIdentityProviderConfig({
            "aws.auth#sigv4": config.credentials
          })
        }));
        this.middlewareStack.use(getHttpSigningPlugin(this.config));
      }
      destroy() {
        super.destroy();
      }
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/models/SigninServiceException.js
var SigninServiceException;
var init_SigninServiceException = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/models/SigninServiceException.js"() {
    init_dist_es27();
    SigninServiceException = class _SigninServiceException extends ServiceException {
      constructor(options) {
        super(options);
        Object.setPrototypeOf(this, _SigninServiceException.prototype);
      }
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/models/errors.js
var AccessDeniedException2, InternalServerException2, TooManyRequestsError, ValidationException;
var init_errors4 = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/models/errors.js"() {
    init_SigninServiceException();
    AccessDeniedException2 = class _AccessDeniedException extends SigninServiceException {
      name = "AccessDeniedException";
      $fault = "client";
      error;
      constructor(opts) {
        super({
          name: "AccessDeniedException",
          $fault: "client",
          ...opts
        });
        Object.setPrototypeOf(this, _AccessDeniedException.prototype);
        this.error = opts.error;
      }
    };
    InternalServerException2 = class _InternalServerException extends SigninServiceException {
      name = "InternalServerException";
      $fault = "server";
      error;
      constructor(opts) {
        super({
          name: "InternalServerException",
          $fault: "server",
          ...opts
        });
        Object.setPrototypeOf(this, _InternalServerException.prototype);
        this.error = opts.error;
      }
    };
    TooManyRequestsError = class _TooManyRequestsError extends SigninServiceException {
      name = "TooManyRequestsError";
      $fault = "client";
      error;
      constructor(opts) {
        super({
          name: "TooManyRequestsError",
          $fault: "client",
          ...opts
        });
        Object.setPrototypeOf(this, _TooManyRequestsError.prototype);
        this.error = opts.error;
      }
    };
    ValidationException = class _ValidationException extends SigninServiceException {
      name = "ValidationException";
      $fault = "client";
      error;
      constructor(opts) {
        super({
          name: "ValidationException",
          $fault: "client",
          ...opts
        });
        Object.setPrototypeOf(this, _ValidationException.prototype);
        this.error = opts.error;
      }
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/schemas/schemas_0.js
var _ADE2, _AT2, _COAT, _COATR, _COATRB, _COATRBr, _COATRr, _ISE2, _RT2, _TMRE2, _VE, _aKI2, _aT3, _c4, _cI2, _cV2, _co2, _e4, _eI2, _gT2, _h3, _hE4, _iT2, _jN, _m3, _rT2, _rU2, _s4, _sAK2, _sT2, _sm2, _tI, _tO, _tT2, n04, RefreshToken2, AccessDeniedException$2, AccessToken$, CreateOAuth2TokenRequest$, CreateOAuth2TokenRequestBody$, CreateOAuth2TokenResponse$, CreateOAuth2TokenResponseBody$, InternalServerException$2, TooManyRequestsError$, ValidationException$, SigninServiceException$, CreateOAuth2Token$;
var init_schemas_04 = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/schemas/schemas_0.js"() {
    init_schema2();
    init_errors4();
    init_SigninServiceException();
    _ADE2 = "AccessDeniedException";
    _AT2 = "AccessToken";
    _COAT = "CreateOAuth2Token";
    _COATR = "CreateOAuth2TokenRequest";
    _COATRB = "CreateOAuth2TokenRequestBody";
    _COATRBr = "CreateOAuth2TokenResponseBody";
    _COATRr = "CreateOAuth2TokenResponse";
    _ISE2 = "InternalServerException";
    _RT2 = "RefreshToken";
    _TMRE2 = "TooManyRequestsError";
    _VE = "ValidationException";
    _aKI2 = "accessKeyId";
    _aT3 = "accessToken";
    _c4 = "client";
    _cI2 = "clientId";
    _cV2 = "codeVerifier";
    _co2 = "code";
    _e4 = "error";
    _eI2 = "expiresIn";
    _gT2 = "grantType";
    _h3 = "http";
    _hE4 = "httpError";
    _iT2 = "idToken";
    _jN = "jsonName";
    _m3 = "message";
    _rT2 = "refreshToken";
    _rU2 = "redirectUri";
    _s4 = "server";
    _sAK2 = "secretAccessKey";
    _sT2 = "sessionToken";
    _sm2 = "smithy.ts.sdk.synthetic.com.amazonaws.signin";
    _tI = "tokenInput";
    _tO = "tokenOutput";
    _tT2 = "tokenType";
    n04 = "com.amazonaws.signin";
    RefreshToken2 = [0, n04, _RT2, 8, 0];
    AccessDeniedException$2 = [-3, n04, _ADE2, { [_e4]: _c4 }, [_e4, _m3], [0, 0]];
    TypeRegistry.for(n04).registerError(AccessDeniedException$2, AccessDeniedException2);
    AccessToken$ = [
      3,
      n04,
      _AT2,
      8,
      [_aKI2, _sAK2, _sT2],
      [
        [0, { [_jN]: _aKI2 }],
        [0, { [_jN]: _sAK2 }],
        [0, { [_jN]: _sT2 }]
      ]
    ];
    CreateOAuth2TokenRequest$ = [
      3,
      n04,
      _COATR,
      0,
      [_tI],
      [[() => CreateOAuth2TokenRequestBody$, 16]]
    ];
    CreateOAuth2TokenRequestBody$ = [
      3,
      n04,
      _COATRB,
      0,
      [_cI2, _gT2, _co2, _rU2, _cV2, _rT2],
      [
        [0, { [_jN]: _cI2 }],
        [0, { [_jN]: _gT2 }],
        0,
        [0, { [_jN]: _rU2 }],
        [0, { [_jN]: _cV2 }],
        [() => RefreshToken2, { [_jN]: _rT2 }]
      ]
    ];
    CreateOAuth2TokenResponse$ = [
      3,
      n04,
      _COATRr,
      0,
      [_tO],
      [[() => CreateOAuth2TokenResponseBody$, 16]]
    ];
    CreateOAuth2TokenResponseBody$ = [
      3,
      n04,
      _COATRBr,
      0,
      [_aT3, _tT2, _eI2, _rT2, _iT2],
      [
        [() => AccessToken$, { [_jN]: _aT3 }],
        [0, { [_jN]: _tT2 }],
        [1, { [_jN]: _eI2 }],
        [() => RefreshToken2, { [_jN]: _rT2 }],
        [0, { [_jN]: _iT2 }]
      ]
    ];
    InternalServerException$2 = [-3, n04, _ISE2, { [_e4]: _s4, [_hE4]: 500 }, [_e4, _m3], [0, 0]];
    TypeRegistry.for(n04).registerError(InternalServerException$2, InternalServerException2);
    TooManyRequestsError$ = [-3, n04, _TMRE2, { [_e4]: _c4, [_hE4]: 429 }, [_e4, _m3], [0, 0]];
    TypeRegistry.for(n04).registerError(TooManyRequestsError$, TooManyRequestsError);
    ValidationException$ = [-3, n04, _VE, { [_e4]: _c4, [_hE4]: 400 }, [_e4, _m3], [0, 0]];
    TypeRegistry.for(n04).registerError(ValidationException$, ValidationException);
    SigninServiceException$ = [-3, _sm2, "SigninServiceException", 0, [], []];
    TypeRegistry.for(_sm2).registerError(SigninServiceException$, SigninServiceException);
    CreateOAuth2Token$ = [
      9,
      n04,
      _COAT,
      { [_h3]: ["POST", "/v1/token", 200] },
      () => CreateOAuth2TokenRequest$,
      () => CreateOAuth2TokenResponse$
    ];
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/commands/CreateOAuth2TokenCommand.js
var CreateOAuth2TokenCommand;
var init_CreateOAuth2TokenCommand = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/commands/CreateOAuth2TokenCommand.js"() {
    init_dist_es36();
    init_dist_es27();
    init_EndpointParameters4();
    init_schemas_04();
    CreateOAuth2TokenCommand = class extends Command.classBuilder().ep(commonParams5).m(function(Command2, cs, config, o6) {
      return [getEndpointPlugin(config, Command2.getEndpointParameterInstructions())];
    }).s("Signin", "CreateOAuth2Token", {}).n("SigninClient", "CreateOAuth2TokenCommand").sc(CreateOAuth2Token$).build() {
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/Signin.js
var commands4, Signin;
var init_Signin = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/Signin.js"() {
    init_dist_es27();
    init_CreateOAuth2TokenCommand();
    init_SigninClient();
    commands4 = {
      CreateOAuth2TokenCommand
    };
    Signin = class extends SigninClient {
    };
    createAggregatedClient(commands4, Signin);
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/commands/index.js
var init_commands4 = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/commands/index.js"() {
    init_CreateOAuth2TokenCommand();
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/models/enums.js
var OAuth2ErrorCode;
var init_enums2 = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/models/enums.js"() {
    OAuth2ErrorCode = {
      AUTHCODE_EXPIRED: "AUTHCODE_EXPIRED",
      INSUFFICIENT_PERMISSIONS: "INSUFFICIENT_PERMISSIONS",
      INVALID_REQUEST: "INVALID_REQUEST",
      SERVER_ERROR: "server_error",
      TOKEN_EXPIRED: "TOKEN_EXPIRED",
      USER_CREDENTIALS_CHANGED: "USER_CREDENTIALS_CHANGED"
    };
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/models/models_0.js
var init_models_04 = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/models/models_0.js"() {
  }
});

// node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/index.js
var signin_exports = {};
__export(signin_exports, {
  $Command: () => Command,
  AccessDeniedException: () => AccessDeniedException2,
  AccessDeniedException$: () => AccessDeniedException$2,
  AccessToken$: () => AccessToken$,
  CreateOAuth2Token$: () => CreateOAuth2Token$,
  CreateOAuth2TokenCommand: () => CreateOAuth2TokenCommand,
  CreateOAuth2TokenRequest$: () => CreateOAuth2TokenRequest$,
  CreateOAuth2TokenRequestBody$: () => CreateOAuth2TokenRequestBody$,
  CreateOAuth2TokenResponse$: () => CreateOAuth2TokenResponse$,
  CreateOAuth2TokenResponseBody$: () => CreateOAuth2TokenResponseBody$,
  InternalServerException: () => InternalServerException2,
  InternalServerException$: () => InternalServerException$2,
  OAuth2ErrorCode: () => OAuth2ErrorCode,
  Signin: () => Signin,
  SigninClient: () => SigninClient,
  SigninServiceException: () => SigninServiceException,
  SigninServiceException$: () => SigninServiceException$,
  TooManyRequestsError: () => TooManyRequestsError,
  TooManyRequestsError$: () => TooManyRequestsError$,
  ValidationException: () => ValidationException,
  ValidationException$: () => ValidationException$,
  __Client: () => Client
});
var init_signin = __esm({
  "node_modules/@aws-sdk/nested-clients/dist-es/submodules/signin/index.js"() {
    init_SigninClient();
    init_Signin();
    init_commands4();
    init_schemas_04();
    init_enums2();
    init_errors4();
    init_models_04();
    init_SigninServiceException();
  }
});

// node_modules/@aws-sdk/credential-provider-login/dist-es/LoginCredentialsFetcher.js
import { createHash as createHash3, createPrivateKey, createPublicKey, sign } from "node:crypto";
import { promises as fs2 } from "node:fs";
import { homedir as homedir2 } from "node:os";
import { dirname, join as join5 } from "node:path";
var LoginCredentialsFetcher;
var init_LoginCredentialsFetcher = __esm({
  "node_modules/@aws-sdk/credential-provider-login/dist-es/LoginCredentialsFetcher.js"() {
    init_dist_es24();
    init_dist_es2();
    init_dist_es34();
    LoginCredentialsFetcher = class _LoginCredentialsFetcher {
      profileData;
      init;
      callerClientConfig;
      static REFRESH_THRESHOLD = 5 * 60 * 1e3;
      constructor(profileData, init, callerClientConfig) {
        this.profileData = profileData;
        this.init = init;
        this.callerClientConfig = callerClientConfig;
      }
      async loadCredentials() {
        const token = await this.loadToken();
        if (!token) {
          throw new CredentialsProviderError(`Failed to load a token for session ${this.loginSession}, please re-authenticate using aws login`, { tryNextLink: false, logger: this.logger });
        }
        const accessToken = token.accessToken;
        const now = Date.now();
        const expiryTime = new Date(accessToken.expiresAt).getTime();
        const timeUntilExpiry = expiryTime - now;
        if (timeUntilExpiry <= _LoginCredentialsFetcher.REFRESH_THRESHOLD) {
          return this.refresh(token);
        }
        return {
          accessKeyId: accessToken.accessKeyId,
          secretAccessKey: accessToken.secretAccessKey,
          sessionToken: accessToken.sessionToken,
          accountId: accessToken.accountId,
          expiration: new Date(accessToken.expiresAt)
        };
      }
      get logger() {
        return this.init?.logger;
      }
      get loginSession() {
        return this.profileData.login_session;
      }
      async refresh(token) {
        const { SigninClient: SigninClient2, CreateOAuth2TokenCommand: CreateOAuth2TokenCommand2 } = await Promise.resolve().then(() => (init_signin(), signin_exports));
        const { logger: logger2, userAgentAppId } = this.callerClientConfig ?? {};
        const isH22 = (requestHandler2) => {
          return requestHandler2?.metadata?.handlerProtocol === "h2";
        };
        const requestHandler = isH22(this.callerClientConfig?.requestHandler) ? void 0 : this.callerClientConfig?.requestHandler;
        const region = this.profileData.region ?? await this.callerClientConfig?.region?.() ?? process.env.AWS_REGION;
        const client = new SigninClient2({
          credentials: {
            accessKeyId: "",
            secretAccessKey: ""
          },
          region,
          requestHandler,
          logger: logger2,
          userAgentAppId,
          ...this.init?.clientConfig
        });
        this.createDPoPInterceptor(client.middlewareStack);
        const commandInput = {
          tokenInput: {
            clientId: token.clientId,
            refreshToken: token.refreshToken,
            grantType: "refresh_token"
          }
        };
        try {
          const response = await client.send(new CreateOAuth2TokenCommand2(commandInput));
          const { accessKeyId, secretAccessKey, sessionToken } = response.tokenOutput?.accessToken ?? {};
          const { refreshToken, expiresIn } = response.tokenOutput ?? {};
          if (!accessKeyId || !secretAccessKey || !sessionToken || !refreshToken) {
            throw new CredentialsProviderError("Token refresh response missing required fields", {
              logger: this.logger,
              tryNextLink: false
            });
          }
          const expiresInMs = (expiresIn ?? 900) * 1e3;
          const expiration = new Date(Date.now() + expiresInMs);
          const updatedToken = {
            ...token,
            accessToken: {
              ...token.accessToken,
              accessKeyId,
              secretAccessKey,
              sessionToken,
              expiresAt: expiration.toISOString()
            },
            refreshToken
          };
          await this.saveToken(updatedToken);
          const newAccessToken = updatedToken.accessToken;
          return {
            accessKeyId: newAccessToken.accessKeyId,
            secretAccessKey: newAccessToken.secretAccessKey,
            sessionToken: newAccessToken.sessionToken,
            accountId: newAccessToken.accountId,
            expiration
          };
        } catch (error) {
          if (error.name === "AccessDeniedException") {
            const errorType = error.error;
            let message;
            switch (errorType) {
              case "TOKEN_EXPIRED":
                message = "Your session has expired. Please reauthenticate.";
                break;
              case "USER_CREDENTIALS_CHANGED":
                message = "Unable to refresh credentials because of a change in your password. Please reauthenticate with your new password.";
                break;
              case "INSUFFICIENT_PERMISSIONS":
                message = "Unable to refresh credentials due to insufficient permissions. You may be missing permission for the 'CreateOAuth2Token' action.";
                break;
              default:
                message = `Failed to refresh token: ${String(error)}. Please re-authenticate using \`aws login\``;
            }
            throw new CredentialsProviderError(message, { logger: this.logger, tryNextLink: false });
          }
          throw new CredentialsProviderError(`Failed to refresh token: ${String(error)}. Please re-authenticate using aws login`, { logger: this.logger });
        }
      }
      async loadToken() {
        const tokenFilePath = this.getTokenFilePath();
        try {
          let tokenData;
          try {
            tokenData = await readFile2(tokenFilePath, { ignoreCache: this.init?.ignoreCache });
          } catch {
            tokenData = await fs2.readFile(tokenFilePath, "utf8");
          }
          const token = JSON.parse(tokenData);
          const missingFields = ["accessToken", "clientId", "refreshToken", "dpopKey"].filter((k6) => !token[k6]);
          if (!token.accessToken?.accountId) {
            missingFields.push("accountId");
          }
          if (missingFields.length > 0) {
            throw new CredentialsProviderError(`Token validation failed, missing fields: ${missingFields.join(", ")}`, {
              logger: this.logger,
              tryNextLink: false
            });
          }
          return token;
        } catch (error) {
          throw new CredentialsProviderError(`Failed to load token from ${tokenFilePath}: ${String(error)}`, {
            logger: this.logger,
            tryNextLink: false
          });
        }
      }
      async saveToken(token) {
        const tokenFilePath = this.getTokenFilePath();
        const directory = dirname(tokenFilePath);
        try {
          await fs2.mkdir(directory, { recursive: true });
        } catch (error) {
        }
        await fs2.writeFile(tokenFilePath, JSON.stringify(token, null, 2), "utf8");
      }
      getTokenFilePath() {
        const directory = process.env.AWS_LOGIN_CACHE_DIRECTORY ?? join5(homedir2(), ".aws", "login", "cache");
        const loginSessionBytes = Buffer.from(this.loginSession, "utf8");
        const loginSessionSha256 = createHash3("sha256").update(loginSessionBytes).digest("hex");
        return join5(directory, `${loginSessionSha256}.json`);
      }
      derToRawSignature(derSignature) {
        let offset = 2;
        if (derSignature[offset] !== 2) {
          throw new Error("Invalid DER signature");
        }
        offset++;
        const rLength = derSignature[offset++];
        let r6 = derSignature.subarray(offset, offset + rLength);
        offset += rLength;
        if (derSignature[offset] !== 2) {
          throw new Error("Invalid DER signature");
        }
        offset++;
        const sLength = derSignature[offset++];
        let s6 = derSignature.subarray(offset, offset + sLength);
        r6 = r6[0] === 0 ? r6.subarray(1) : r6;
        s6 = s6[0] === 0 ? s6.subarray(1) : s6;
        const rPadded = Buffer.concat([Buffer.alloc(32 - r6.length), r6]);
        const sPadded = Buffer.concat([Buffer.alloc(32 - s6.length), s6]);
        return Buffer.concat([rPadded, sPadded]);
      }
      createDPoPInterceptor(middlewareStack) {
        middlewareStack.add((next) => async (args) => {
          if (HttpRequest.isInstance(args.request)) {
            const request2 = args.request;
            const actualEndpoint = `${request2.protocol}//${request2.hostname}${request2.port ? `:${request2.port}` : ""}${request2.path}`;
            const dpop = await this.generateDpop(request2.method, actualEndpoint);
            request2.headers = {
              ...request2.headers,
              DPoP: dpop
            };
          }
          return next(args);
        }, {
          step: "finalizeRequest",
          name: "dpopInterceptor",
          override: true
        });
      }
      async generateDpop(method = "POST", endpoint) {
        const token = await this.loadToken();
        try {
          const privateKey = createPrivateKey({
            key: token.dpopKey,
            format: "pem",
            type: "sec1"
          });
          const publicKey = createPublicKey(privateKey);
          const publicDer = publicKey.export({ format: "der", type: "spki" });
          let pointStart = -1;
          for (let i6 = 0; i6 < publicDer.length; i6++) {
            if (publicDer[i6] === 4) {
              pointStart = i6;
              break;
            }
          }
          const x5 = publicDer.slice(pointStart + 1, pointStart + 33);
          const y2 = publicDer.slice(pointStart + 33, pointStart + 65);
          const header = {
            alg: "ES256",
            typ: "dpop+jwt",
            jwk: {
              kty: "EC",
              crv: "P-256",
              x: x5.toString("base64url"),
              y: y2.toString("base64url")
            }
          };
          const payload = {
            jti: crypto.randomUUID(),
            htm: method,
            htu: endpoint,
            iat: Math.floor(Date.now() / 1e3)
          };
          const headerB64 = Buffer.from(JSON.stringify(header)).toString("base64url");
          const payloadB64 = Buffer.from(JSON.stringify(payload)).toString("base64url");
          const message = `${headerB64}.${payloadB64}`;
          const asn1Signature = sign("sha256", Buffer.from(message), privateKey);
          const rawSignature = this.derToRawSignature(asn1Signature);
          const signatureB64 = rawSignature.toString("base64url");
          return `${message}.${signatureB64}`;
        } catch (error) {
          throw new CredentialsProviderError(`Failed to generate Dpop proof: ${error instanceof Error ? error.message : String(error)}`, { logger: this.logger, tryNextLink: false });
        }
      }
    };
  }
});

// node_modules/@aws-sdk/credential-provider-login/dist-es/fromLoginCredentials.js
var fromLoginCredentials;
var init_fromLoginCredentials = __esm({
  "node_modules/@aws-sdk/credential-provider-login/dist-es/fromLoginCredentials.js"() {
    init_client2();
    init_dist_es24();
    init_dist_es34();
    init_LoginCredentialsFetcher();
    fromLoginCredentials = (init) => async ({ callerClientConfig } = {}) => {
      init?.logger?.debug?.("@aws-sdk/credential-providers - fromLoginCredentials");
      const profiles = await parseKnownFiles(init || {});
      const profileName = getProfileName({
        profile: init?.profile ?? callerClientConfig?.profile
      });
      const profile = profiles[profileName];
      if (!profile?.login_session) {
        throw new CredentialsProviderError(`Profile ${profileName} does not contain login_session.`, {
          tryNextLink: true,
          logger: init?.logger
        });
      }
      const fetcher = new LoginCredentialsFetcher(profile, init, callerClientConfig);
      const credentials = await fetcher.loadCredentials();
      return setCredentialFeature(credentials, "CREDENTIALS_LOGIN", "AD");
    };
  }
});

// node_modules/@aws-sdk/credential-provider-login/dist-es/types.js
var init_types10 = __esm({
  "node_modules/@aws-sdk/credential-provider-login/dist-es/types.js"() {
  }
});

// node_modules/@aws-sdk/credential-provider-login/dist-es/index.js
var init_dist_es51 = __esm({
  "node_modules/@aws-sdk/credential-provider-login/dist-es/index.js"() {
    init_fromLoginCredentials();
    init_types10();
  }
});

// node_modules/@aws-sdk/credential-provider-ini/dist-es/resolveLoginCredentials.js
var isLoginProfile, resolveLoginCredentials;
var init_resolveLoginCredentials = __esm({
  "node_modules/@aws-sdk/credential-provider-ini/dist-es/resolveLoginCredentials.js"() {
    init_client2();
    init_dist_es51();
    isLoginProfile = (data) => {
      return Boolean(data && data.login_session);
    };
    resolveLoginCredentials = async (profileName, options, callerClientConfig) => {
      const credentials = await fromLoginCredentials({
        ...options,
        profile: profileName
      })({ callerClientConfig });
      return setCredentialFeature(credentials, "CREDENTIALS_PROFILE_LOGIN", "AC");
    };
  }
});

// node_modules/@aws-sdk/credential-provider-process/dist-es/getValidatedProcessCredentials.js
var getValidatedProcessCredentials;
var init_getValidatedProcessCredentials = __esm({
  "node_modules/@aws-sdk/credential-provider-process/dist-es/getValidatedProcessCredentials.js"() {
    init_client2();
    getValidatedProcessCredentials = (profileName, data, profiles) => {
      if (data.Version !== 1) {
        throw Error(`Profile ${profileName} credential_process did not return Version 1.`);
      }
      if (data.AccessKeyId === void 0 || data.SecretAccessKey === void 0) {
        throw Error(`Profile ${profileName} credential_process returned invalid credentials.`);
      }
      if (data.Expiration) {
        const currentTime = /* @__PURE__ */ new Date();
        const expireTime = new Date(data.Expiration);
        if (expireTime < currentTime) {
          throw Error(`Profile ${profileName} credential_process returned expired credentials.`);
        }
      }
      let accountId = data.AccountId;
      if (!accountId && profiles?.[profileName]?.aws_account_id) {
        accountId = profiles[profileName].aws_account_id;
      }
      const credentials = {
        accessKeyId: data.AccessKeyId,
        secretAccessKey: data.SecretAccessKey,
        ...data.SessionToken && { sessionToken: data.SessionToken },
        ...data.Expiration && { expiration: new Date(data.Expiration) },
        ...data.CredentialScope && { credentialScope: data.CredentialScope },
        ...accountId && { accountId }
      };
      setCredentialFeature(credentials, "CREDENTIALS_PROCESS", "w");
      return credentials;
    };
  }
});

// node_modules/@aws-sdk/credential-provider-process/dist-es/resolveProcessCredentials.js
import { exec } from "child_process";
import { promisify } from "util";
var resolveProcessCredentials;
var init_resolveProcessCredentials = __esm({
  "node_modules/@aws-sdk/credential-provider-process/dist-es/resolveProcessCredentials.js"() {
    init_dist_es24();
    init_dist_es34();
    init_getValidatedProcessCredentials();
    resolveProcessCredentials = async (profileName, profiles, logger2) => {
      const profile = profiles[profileName];
      if (profiles[profileName]) {
        const credentialProcess = profile["credential_process"];
        if (credentialProcess !== void 0) {
          const execPromise = promisify(externalDataInterceptor?.getTokenRecord?.().exec ?? exec);
          try {
            const { stdout } = await execPromise(credentialProcess);
            let data;
            try {
              data = JSON.parse(stdout.trim());
            } catch {
              throw Error(`Profile ${profileName} credential_process returned invalid JSON.`);
            }
            return getValidatedProcessCredentials(profileName, data, profiles);
          } catch (error) {
            throw new CredentialsProviderError(error.message, { logger: logger2 });
          }
        } else {
          throw new CredentialsProviderError(`Profile ${profileName} did not contain credential_process.`, { logger: logger2 });
        }
      } else {
        throw new CredentialsProviderError(`Profile ${profileName} could not be found in shared credentials file.`, {
          logger: logger2
        });
      }
    };
  }
});

// node_modules/@aws-sdk/credential-provider-process/dist-es/fromProcess.js
var fromProcess;
var init_fromProcess = __esm({
  "node_modules/@aws-sdk/credential-provider-process/dist-es/fromProcess.js"() {
    init_dist_es34();
    init_resolveProcessCredentials();
    fromProcess = (init = {}) => async ({ callerClientConfig } = {}) => {
      init.logger?.debug("@aws-sdk/credential-provider-process - fromProcess");
      const profiles = await parseKnownFiles(init);
      return resolveProcessCredentials(getProfileName({
        profile: init.profile ?? callerClientConfig?.profile
      }), profiles, init.logger);
    };
  }
});

// node_modules/@aws-sdk/credential-provider-process/dist-es/index.js
var dist_es_exports5 = {};
__export(dist_es_exports5, {
  fromProcess: () => fromProcess
});
var init_dist_es52 = __esm({
  "node_modules/@aws-sdk/credential-provider-process/dist-es/index.js"() {
    init_fromProcess();
  }
});

// node_modules/@aws-sdk/credential-provider-ini/dist-es/resolveProcessCredentials.js
var isProcessProfile, resolveProcessCredentials2;
var init_resolveProcessCredentials2 = __esm({
  "node_modules/@aws-sdk/credential-provider-ini/dist-es/resolveProcessCredentials.js"() {
    init_client2();
    isProcessProfile = (arg) => Boolean(arg) && typeof arg === "object" && typeof arg.credential_process === "string";
    resolveProcessCredentials2 = async (options, profile) => Promise.resolve().then(() => (init_dist_es52(), dist_es_exports5)).then(({ fromProcess: fromProcess2 }) => fromProcess2({
      ...options,
      profile
    })().then((creds) => setCredentialFeature(creds, "CREDENTIALS_PROFILE_PROCESS", "v")));
  }
});

// node_modules/@aws-sdk/credential-provider-ini/dist-es/resolveSsoCredentials.js
var resolveSsoCredentials, isSsoProfile2;
var init_resolveSsoCredentials = __esm({
  "node_modules/@aws-sdk/credential-provider-ini/dist-es/resolveSsoCredentials.js"() {
    init_client2();
    resolveSsoCredentials = async (profile, profileData, options = {}, callerClientConfig) => {
      const { fromSSO: fromSSO2 } = await Promise.resolve().then(() => (init_dist_es50(), dist_es_exports4));
      return fromSSO2({
        profile,
        logger: options.logger,
        parentClientConfig: options.parentClientConfig,
        clientConfig: options.clientConfig
      })({
        callerClientConfig
      }).then((creds) => {
        if (profileData.sso_session) {
          return setCredentialFeature(creds, "CREDENTIALS_PROFILE_SSO", "r");
        } else {
          return setCredentialFeature(creds, "CREDENTIALS_PROFILE_SSO_LEGACY", "t");
        }
      });
    };
    isSsoProfile2 = (arg) => arg && (typeof arg.sso_start_url === "string" || typeof arg.sso_account_id === "string" || typeof arg.sso_session === "string" || typeof arg.sso_region === "string" || typeof arg.sso_role_name === "string");
  }
});

// node_modules/@aws-sdk/credential-provider-ini/dist-es/resolveStaticCredentials.js
var isStaticCredsProfile, resolveStaticCredentials;
var init_resolveStaticCredentials = __esm({
  "node_modules/@aws-sdk/credential-provider-ini/dist-es/resolveStaticCredentials.js"() {
    init_client2();
    isStaticCredsProfile = (arg) => Boolean(arg) && typeof arg === "object" && typeof arg.aws_access_key_id === "string" && typeof arg.aws_secret_access_key === "string" && ["undefined", "string"].indexOf(typeof arg.aws_session_token) > -1 && ["undefined", "string"].indexOf(typeof arg.aws_account_id) > -1;
    resolveStaticCredentials = async (profile, options) => {
      options?.logger?.debug("@aws-sdk/credential-provider-ini - resolveStaticCredentials");
      const credentials = {
        accessKeyId: profile.aws_access_key_id,
        secretAccessKey: profile.aws_secret_access_key,
        sessionToken: profile.aws_session_token,
        ...profile.aws_credential_scope && { credentialScope: profile.aws_credential_scope },
        ...profile.aws_account_id && { accountId: profile.aws_account_id }
      };
      return setCredentialFeature(credentials, "CREDENTIALS_PROFILE", "n");
    };
  }
});

// node_modules/@aws-sdk/credential-provider-web-identity/dist-es/fromWebToken.js
var fromWebToken;
var init_fromWebToken = __esm({
  "node_modules/@aws-sdk/credential-provider-web-identity/dist-es/fromWebToken.js"() {
    fromWebToken = (init) => async (awsIdentityProperties) => {
      init.logger?.debug("@aws-sdk/credential-provider-web-identity - fromWebToken");
      const { roleArn, roleSessionName, webIdentityToken, providerId, policyArns, policy, durationSeconds } = init;
      let { roleAssumerWithWebIdentity } = init;
      if (!roleAssumerWithWebIdentity) {
        const { getDefaultRoleAssumerWithWebIdentity: getDefaultRoleAssumerWithWebIdentity3 } = await Promise.resolve().then(() => (init_sts(), sts_exports));
        roleAssumerWithWebIdentity = getDefaultRoleAssumerWithWebIdentity3({
          ...init.clientConfig,
          credentialProviderLogger: init.logger,
          parentClientConfig: {
            ...awsIdentityProperties?.callerClientConfig,
            ...init.parentClientConfig
          }
        }, init.clientPlugins);
      }
      return roleAssumerWithWebIdentity({
        RoleArn: roleArn,
        RoleSessionName: roleSessionName ?? `aws-sdk-js-session-${Date.now()}`,
        WebIdentityToken: webIdentityToken,
        ProviderId: providerId,
        PolicyArns: policyArns,
        Policy: policy,
        DurationSeconds: durationSeconds
      });
    };
  }
});

// node_modules/@aws-sdk/credential-provider-web-identity/dist-es/fromTokenFile.js
import { readFileSync } from "fs";
var ENV_TOKEN_FILE, ENV_ROLE_ARN, ENV_ROLE_SESSION_NAME, fromTokenFile;
var init_fromTokenFile = __esm({
  "node_modules/@aws-sdk/credential-provider-web-identity/dist-es/fromTokenFile.js"() {
    init_client2();
    init_dist_es24();
    init_dist_es34();
    init_fromWebToken();
    ENV_TOKEN_FILE = "AWS_WEB_IDENTITY_TOKEN_FILE";
    ENV_ROLE_ARN = "AWS_ROLE_ARN";
    ENV_ROLE_SESSION_NAME = "AWS_ROLE_SESSION_NAME";
    fromTokenFile = (init = {}) => async (awsIdentityProperties) => {
      init.logger?.debug("@aws-sdk/credential-provider-web-identity - fromTokenFile");
      const webIdentityTokenFile = init?.webIdentityTokenFile ?? process.env[ENV_TOKEN_FILE];
      const roleArn = init?.roleArn ?? process.env[ENV_ROLE_ARN];
      const roleSessionName = init?.roleSessionName ?? process.env[ENV_ROLE_SESSION_NAME];
      if (!webIdentityTokenFile || !roleArn) {
        throw new CredentialsProviderError("Web identity configuration not specified", {
          logger: init.logger
        });
      }
      const credentials = await fromWebToken({
        ...init,
        webIdentityToken: externalDataInterceptor?.getTokenRecord?.()[webIdentityTokenFile] ?? readFileSync(webIdentityTokenFile, { encoding: "ascii" }),
        roleArn,
        roleSessionName
      })(awsIdentityProperties);
      if (webIdentityTokenFile === process.env[ENV_TOKEN_FILE]) {
        setCredentialFeature(credentials, "CREDENTIALS_ENV_VARS_STS_WEB_ID_TOKEN", "h");
      }
      return credentials;
    };
  }
});

// node_modules/@aws-sdk/credential-provider-web-identity/dist-es/index.js
var dist_es_exports6 = {};
__export(dist_es_exports6, {
  fromTokenFile: () => fromTokenFile,
  fromWebToken: () => fromWebToken
});
var init_dist_es53 = __esm({
  "node_modules/@aws-sdk/credential-provider-web-identity/dist-es/index.js"() {
    init_fromTokenFile();
    init_fromWebToken();
  }
});

// node_modules/@aws-sdk/credential-provider-ini/dist-es/resolveWebIdentityCredentials.js
var isWebIdentityProfile, resolveWebIdentityCredentials;
var init_resolveWebIdentityCredentials = __esm({
  "node_modules/@aws-sdk/credential-provider-ini/dist-es/resolveWebIdentityCredentials.js"() {
    init_client2();
    isWebIdentityProfile = (arg) => Boolean(arg) && typeof arg === "object" && typeof arg.web_identity_token_file === "string" && typeof arg.role_arn === "string" && ["undefined", "string"].indexOf(typeof arg.role_session_name) > -1;
    resolveWebIdentityCredentials = async (profile, options, callerClientConfig) => Promise.resolve().then(() => (init_dist_es53(), dist_es_exports6)).then(({ fromTokenFile: fromTokenFile2 }) => fromTokenFile2({
      webIdentityTokenFile: profile.web_identity_token_file,
      roleArn: profile.role_arn,
      roleSessionName: profile.role_session_name,
      roleAssumerWithWebIdentity: options.roleAssumerWithWebIdentity,
      logger: options.logger,
      parentClientConfig: options.parentClientConfig
    })({
      callerClientConfig
    }).then((creds) => setCredentialFeature(creds, "CREDENTIALS_PROFILE_STS_WEB_ID_TOKEN", "q")));
  }
});

// node_modules/@aws-sdk/credential-provider-ini/dist-es/resolveProfileData.js
var resolveProfileData;
var init_resolveProfileData = __esm({
  "node_modules/@aws-sdk/credential-provider-ini/dist-es/resolveProfileData.js"() {
    init_dist_es24();
    init_resolveAssumeRoleCredentials();
    init_resolveLoginCredentials();
    init_resolveProcessCredentials2();
    init_resolveSsoCredentials();
    init_resolveStaticCredentials();
    init_resolveWebIdentityCredentials();
    resolveProfileData = async (profileName, profiles, options, callerClientConfig, visitedProfiles = {}, isAssumeRoleRecursiveCall = false) => {
      const data = profiles[profileName];
      if (Object.keys(visitedProfiles).length > 0 && isStaticCredsProfile(data)) {
        return resolveStaticCredentials(data, options);
      }
      if (isAssumeRoleRecursiveCall || isAssumeRoleProfile(data, { profile: profileName, logger: options.logger })) {
        return resolveAssumeRoleCredentials(profileName, profiles, options, callerClientConfig, visitedProfiles, resolveProfileData);
      }
      if (isStaticCredsProfile(data)) {
        return resolveStaticCredentials(data, options);
      }
      if (isWebIdentityProfile(data)) {
        return resolveWebIdentityCredentials(data, options, callerClientConfig);
      }
      if (isProcessProfile(data)) {
        return resolveProcessCredentials2(options, profileName);
      }
      if (isSsoProfile2(data)) {
        return await resolveSsoCredentials(profileName, data, options, callerClientConfig);
      }
      if (isLoginProfile(data)) {
        return resolveLoginCredentials(profileName, options, callerClientConfig);
      }
      throw new CredentialsProviderError(`Could not resolve credentials using profile: [${profileName}] in configuration/credentials file(s).`, { logger: options.logger });
    };
  }
});

// node_modules/@aws-sdk/credential-provider-ini/dist-es/fromIni.js
var fromIni;
var init_fromIni = __esm({
  "node_modules/@aws-sdk/credential-provider-ini/dist-es/fromIni.js"() {
    init_dist_es34();
    init_resolveProfileData();
    fromIni = (init = {}) => async ({ callerClientConfig } = {}) => {
      init.logger?.debug("@aws-sdk/credential-provider-ini - fromIni");
      const profiles = await parseKnownFiles(init);
      return resolveProfileData(getProfileName({
        profile: init.profile ?? callerClientConfig?.profile
      }), profiles, init, callerClientConfig);
    };
  }
});

// node_modules/@aws-sdk/credential-provider-ini/dist-es/index.js
var dist_es_exports7 = {};
__export(dist_es_exports7, {
  fromIni: () => fromIni
});
var init_dist_es54 = __esm({
  "node_modules/@aws-sdk/credential-provider-ini/dist-es/index.js"() {
    init_fromIni();
  }
});

// lambdas/shared/token-handler.ts
import { DynamoDBClient, GetItemCommand, DeleteItemCommand } from "@aws-sdk/client-dynamodb";
import { LambdaClient, SendDurableExecutionCallbackSuccessCommand } from "@aws-sdk/client-lambda";

// node_modules/@aws-sdk/client-sfn/dist-es/SFNClient.js
init_dist_es3();
init_dist_es4();
init_dist_es5();
init_dist_es30();
init_dist_es32();
init_dist_es19();
init_schema2();
init_dist_es33();
init_dist_es36();
init_dist_es39();
init_dist_es27();

// node_modules/@aws-sdk/client-sfn/dist-es/auth/httpAuthSchemeProvider.js
init_dist_es29();
init_dist_es6();
var defaultSFNHttpAuthSchemeParametersProvider = async (config, context, input) => {
  return {
    operation: getSmithyContext(context).operation,
    region: await normalizeProvider(config.region)() || (() => {
      throw new Error("expected `region` to be configured for `aws.auth#sigv4`");
    })()
  };
};
function createAwsAuthSigv4HttpAuthOption(authParameters) {
  return {
    schemeId: "aws.auth#sigv4",
    signingProperties: {
      name: "states",
      region: authParameters.region
    },
    propertiesExtractor: (config, context) => ({
      signingProperties: {
        config,
        context
      }
    })
  };
}
var defaultSFNHttpAuthSchemeProvider = (authParameters) => {
  const options = [];
  switch (authParameters.operation) {
    default: {
      options.push(createAwsAuthSigv4HttpAuthOption(authParameters));
    }
  }
  return options;
};
var resolveHttpAuthSchemeConfig = (config) => {
  const config_0 = resolveAwsSdkSigV4Config(config);
  return Object.assign(config_0, {
    authSchemePreference: normalizeProvider(config.authSchemePreference ?? [])
  });
};

// node_modules/@aws-sdk/client-sfn/dist-es/endpoint/EndpointParameters.js
var resolveClientEndpointParameters = (options) => {
  return Object.assign(options, {
    useDualstackEndpoint: options.useDualstackEndpoint ?? false,
    useFipsEndpoint: options.useFipsEndpoint ?? false,
    defaultSigningName: "states"
  });
};
var commonParams = {
  UseFIPS: { type: "builtInParams", name: "useFipsEndpoint" },
  Endpoint: { type: "builtInParams", name: "endpoint" },
  Region: { type: "builtInParams", name: "region" },
  UseDualStack: { type: "builtInParams", name: "useDualstackEndpoint" }
};

// node_modules/@aws-sdk/client-sfn/package.json
var package_default = {
  name: "@aws-sdk/client-sfn",
  description: "AWS SDK for JavaScript Sfn Client for Node.js, Browser and React Native",
  version: "3.956.0",
  scripts: {
    build: "concurrently 'yarn:build:types' 'yarn:build:es' && yarn build:cjs",
    "build:cjs": "node ../../scripts/compilation/inline client-sfn",
    "build:es": "tsc -p tsconfig.es.json",
    "build:include:deps": "lerna run --scope $npm_package_name --include-dependencies build",
    "build:types": "tsc -p tsconfig.types.json",
    "build:types:downlevel": "downlevel-dts dist-types dist-types/ts3.4",
    clean: "rimraf ./dist-* && rimraf *.tsbuildinfo",
    "extract:docs": "api-extractor run --local",
    "generate:client": "node ../../scripts/generate-clients/single-service --solo sfn",
    "test:index": "tsc --noEmit ./test/index-types.ts && node ./test/index-objects.spec.mjs"
  },
  main: "./dist-cjs/index.js",
  types: "./dist-types/index.d.ts",
  module: "./dist-es/index.js",
  sideEffects: false,
  dependencies: {
    "@aws-crypto/sha256-browser": "5.2.0",
    "@aws-crypto/sha256-js": "5.2.0",
    "@aws-sdk/core": "3.956.0",
    "@aws-sdk/credential-provider-node": "3.956.0",
    "@aws-sdk/middleware-host-header": "3.956.0",
    "@aws-sdk/middleware-logger": "3.956.0",
    "@aws-sdk/middleware-recursion-detection": "3.956.0",
    "@aws-sdk/middleware-user-agent": "3.956.0",
    "@aws-sdk/region-config-resolver": "3.956.0",
    "@aws-sdk/types": "3.956.0",
    "@aws-sdk/util-endpoints": "3.956.0",
    "@aws-sdk/util-user-agent-browser": "3.956.0",
    "@aws-sdk/util-user-agent-node": "3.956.0",
    "@smithy/config-resolver": "^4.4.5",
    "@smithy/core": "^3.20.0",
    "@smithy/fetch-http-handler": "^5.3.8",
    "@smithy/hash-node": "^4.2.7",
    "@smithy/invalid-dependency": "^4.2.7",
    "@smithy/middleware-content-length": "^4.2.7",
    "@smithy/middleware-endpoint": "^4.4.1",
    "@smithy/middleware-retry": "^4.4.17",
    "@smithy/middleware-serde": "^4.2.8",
    "@smithy/middleware-stack": "^4.2.7",
    "@smithy/node-config-provider": "^4.3.7",
    "@smithy/node-http-handler": "^4.4.7",
    "@smithy/protocol-http": "^5.3.7",
    "@smithy/smithy-client": "^4.10.2",
    "@smithy/types": "^4.11.0",
    "@smithy/url-parser": "^4.2.7",
    "@smithy/util-base64": "^4.3.0",
    "@smithy/util-body-length-browser": "^4.2.0",
    "@smithy/util-body-length-node": "^4.2.1",
    "@smithy/util-defaults-mode-browser": "^4.3.16",
    "@smithy/util-defaults-mode-node": "^4.2.19",
    "@smithy/util-endpoints": "^3.2.7",
    "@smithy/util-middleware": "^4.2.7",
    "@smithy/util-retry": "^4.2.7",
    "@smithy/util-utf8": "^4.2.0",
    tslib: "^2.6.2"
  },
  devDependencies: {
    "@tsconfig/node18": "18.2.4",
    "@types/node": "^18.19.69",
    concurrently: "7.0.0",
    "downlevel-dts": "0.10.1",
    rimraf: "3.0.2",
    typescript: "~5.8.3"
  },
  engines: {
    node: ">=18.0.0"
  },
  typesVersions: {
    "<4.0": {
      "dist-types/*": [
        "dist-types/ts3.4/*"
      ]
    }
  },
  files: [
    "dist-*/**"
  ],
  author: {
    name: "AWS SDK for JavaScript Team",
    url: "https://aws.amazon.com/javascript/"
  },
  license: "Apache-2.0",
  browser: {
    "./dist-es/runtimeConfig": "./dist-es/runtimeConfig.browser"
  },
  "react-native": {
    "./dist-es/runtimeConfig": "./dist-es/runtimeConfig.native"
  },
  homepage: "https://github.com/aws/aws-sdk-js-v3/tree/main/clients/client-sfn",
  repository: {
    type: "git",
    url: "https://github.com/aws/aws-sdk-js-v3.git",
    directory: "clients/client-sfn"
  }
};

// node_modules/@aws-sdk/client-sfn/dist-es/runtimeConfig.js
init_dist_es29();

// node_modules/@aws-sdk/credential-provider-node/dist-es/defaultProvider.js
init_dist_es40();
init_dist_es24();
init_dist_es34();

// node_modules/@aws-sdk/credential-provider-node/dist-es/remoteProvider.js
init_dist_es24();
var ENV_IMDS_DISABLED = "AWS_EC2_METADATA_DISABLED";
var remoteProvider = async (init) => {
  const { ENV_CMDS_FULL_URI: ENV_CMDS_FULL_URI2, ENV_CMDS_RELATIVE_URI: ENV_CMDS_RELATIVE_URI2, fromContainerMetadata: fromContainerMetadata2, fromInstanceMetadata: fromInstanceMetadata2 } = await Promise.resolve().then(() => (init_dist_es41(), dist_es_exports2));
  if (process.env[ENV_CMDS_RELATIVE_URI2] || process.env[ENV_CMDS_FULL_URI2]) {
    init.logger?.debug("@aws-sdk/credential-provider-node - remoteProvider::fromHttp/fromContainerMetadata");
    const { fromHttp: fromHttp2 } = await Promise.resolve().then(() => (init_dist_es42(), dist_es_exports3));
    return chain(fromHttp2(init), fromContainerMetadata2(init));
  }
  if (process.env[ENV_IMDS_DISABLED] && process.env[ENV_IMDS_DISABLED] !== "false") {
    return async () => {
      throw new CredentialsProviderError("EC2 Instance Metadata Service access disabled", { logger: init.logger });
    };
  }
  init.logger?.debug("@aws-sdk/credential-provider-node - remoteProvider::fromInstanceMetadata");
  return fromInstanceMetadata2(init);
};

// node_modules/@aws-sdk/credential-provider-node/dist-es/runtime/memoize-chain.js
function memoizeChain(providers, treatAsExpired) {
  const chain2 = internalCreateChain(providers);
  let activeLock;
  let passiveLock;
  let credentials;
  const provider = async (options) => {
    if (options?.forceRefresh) {
      return await chain2(options);
    }
    if (credentials?.expiration) {
      if (credentials?.expiration?.getTime() < Date.now()) {
        credentials = void 0;
      }
    }
    if (activeLock) {
      await activeLock;
    } else if (!credentials || treatAsExpired?.(credentials)) {
      if (credentials) {
        if (!passiveLock) {
          passiveLock = chain2(options).then((c6) => {
            credentials = c6;
            passiveLock = void 0;
          });
        }
      } else {
        activeLock = chain2(options).then((c6) => {
          credentials = c6;
          activeLock = void 0;
        });
        return provider(options);
      }
    }
    return credentials;
  };
  return provider;
}
var internalCreateChain = (providers) => async (awsIdentityProperties) => {
  let lastProviderError;
  for (const provider of providers) {
    try {
      return await provider(awsIdentityProperties);
    } catch (err) {
      lastProviderError = err;
      if (err?.tryNextLink) {
        continue;
      }
      throw err;
    }
  }
  throw lastProviderError;
};

// node_modules/@aws-sdk/credential-provider-node/dist-es/defaultProvider.js
var multipleCredentialSourceWarningEmitted = false;
var defaultProvider = (init = {}) => memoizeChain([
  async () => {
    const profile = init.profile ?? process.env[ENV_PROFILE];
    if (profile) {
      const envStaticCredentialsAreSet = process.env[ENV_KEY] && process.env[ENV_SECRET];
      if (envStaticCredentialsAreSet) {
        if (!multipleCredentialSourceWarningEmitted) {
          const warnFn = init.logger?.warn && init.logger?.constructor?.name !== "NoOpLogger" ? init.logger.warn.bind(init.logger) : console.warn;
          warnFn(`@aws-sdk/credential-provider-node - defaultProvider::fromEnv WARNING:
    Multiple credential sources detected: 
    Both AWS_PROFILE and the pair AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY static credentials are set.
    This SDK will proceed with the AWS_PROFILE value.
    
    However, a future version may change this behavior to prefer the ENV static credentials.
    Please ensure that your environment only sets either the AWS_PROFILE or the
    AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY pair.
`);
          multipleCredentialSourceWarningEmitted = true;
        }
      }
      throw new CredentialsProviderError("AWS_PROFILE is set, skipping fromEnv provider.", {
        logger: init.logger,
        tryNextLink: true
      });
    }
    init.logger?.debug("@aws-sdk/credential-provider-node - defaultProvider::fromEnv");
    return fromEnv2(init)();
  },
  async (awsIdentityProperties) => {
    init.logger?.debug("@aws-sdk/credential-provider-node - defaultProvider::fromSSO");
    const { ssoStartUrl, ssoAccountId, ssoRegion, ssoRoleName, ssoSession } = init;
    if (!ssoStartUrl && !ssoAccountId && !ssoRegion && !ssoRoleName && !ssoSession) {
      throw new CredentialsProviderError("Skipping SSO provider in default chain (inputs do not include SSO fields).", { logger: init.logger });
    }
    const { fromSSO: fromSSO2 } = await Promise.resolve().then(() => (init_dist_es50(), dist_es_exports4));
    return fromSSO2(init)(awsIdentityProperties);
  },
  async (awsIdentityProperties) => {
    init.logger?.debug("@aws-sdk/credential-provider-node - defaultProvider::fromIni");
    const { fromIni: fromIni2 } = await Promise.resolve().then(() => (init_dist_es54(), dist_es_exports7));
    return fromIni2(init)(awsIdentityProperties);
  },
  async (awsIdentityProperties) => {
    init.logger?.debug("@aws-sdk/credential-provider-node - defaultProvider::fromProcess");
    const { fromProcess: fromProcess2 } = await Promise.resolve().then(() => (init_dist_es52(), dist_es_exports5));
    return fromProcess2(init)(awsIdentityProperties);
  },
  async (awsIdentityProperties) => {
    init.logger?.debug("@aws-sdk/credential-provider-node - defaultProvider::fromTokenFile");
    const { fromTokenFile: fromTokenFile2 } = await Promise.resolve().then(() => (init_dist_es53(), dist_es_exports6));
    return fromTokenFile2(init)(awsIdentityProperties);
  },
  async () => {
    init.logger?.debug("@aws-sdk/credential-provider-node - defaultProvider::remoteProvider");
    return (await remoteProvider(init))();
  },
  async () => {
    throw new CredentialsProviderError("Could not load credentials from any providers", {
      tryNextLink: false,
      logger: init.logger
    });
  }
], credentialsTreatedAsExpired);
var credentialsTreatedAsExpired = (credentials) => credentials?.expiration !== void 0 && credentials.expiration.getTime() - Date.now() < 3e5;

// node_modules/@aws-sdk/client-sfn/dist-es/runtimeConfig.js
init_dist_es43();
init_dist_es32();
init_dist_es44();
init_dist_es39();
init_dist_es35();
init_dist_es14();
init_dist_es27();
init_dist_es45();
init_dist_es46();
init_dist_es38();

// node_modules/@aws-sdk/client-sfn/dist-es/runtimeConfig.shared.js
init_dist_es29();
init_protocols2();
init_dist_es27();
init_dist_es22();
init_dist_es11();
init_dist_es10();

// node_modules/@aws-sdk/client-sfn/dist-es/endpoint/endpointResolver.js
init_dist_es23();
init_dist_es20();

// node_modules/@aws-sdk/client-sfn/dist-es/endpoint/ruleset.js
var t5 = "required";
var u5 = "fn";
var v6 = "argv";
var w5 = "ref";
var a5 = true;
var b5 = "isSet";
var c5 = "booleanEquals";
var d5 = "error";
var e5 = "endpoint";
var f5 = "tree";
var g5 = "PartitionResult";
var h5 = { [t5]: false, "type": "string" };
var i5 = { [t5]: true, "default": false, "type": "boolean" };
var j5 = { [w5]: "Endpoint" };
var k5 = { [u5]: c5, [v6]: [{ [w5]: "UseFIPS" }, true] };
var l5 = { [u5]: c5, [v6]: [{ [w5]: "UseDualStack" }, true] };
var m5 = {};
var n5 = { [w5]: "Region" };
var o5 = { [u5]: "getAttr", [v6]: [{ [w5]: g5 }, "supportsFIPS"] };
var p5 = { [u5]: c5, [v6]: [true, { [u5]: "getAttr", [v6]: [{ [w5]: g5 }, "supportsDualStack"] }] };
var q5 = [k5];
var r5 = [l5];
var s5 = [n5];
var _data5 = { version: "1.0", parameters: { Region: h5, UseDualStack: i5, UseFIPS: i5, Endpoint: h5 }, rules: [{ conditions: [{ [u5]: b5, [v6]: [j5] }], rules: [{ conditions: q5, error: "Invalid Configuration: FIPS and custom endpoint are not supported", type: d5 }, { conditions: r5, error: "Invalid Configuration: Dualstack and custom endpoint are not supported", type: d5 }, { endpoint: { url: j5, properties: m5, headers: m5 }, type: e5 }], type: f5 }, { conditions: [{ [u5]: b5, [v6]: s5 }], rules: [{ conditions: [{ [u5]: "aws.partition", [v6]: s5, assign: g5 }], rules: [{ conditions: [k5, l5], rules: [{ conditions: [{ [u5]: c5, [v6]: [a5, o5] }, p5], rules: [{ endpoint: { url: "https://states-fips.{Region}.{PartitionResult#dualStackDnsSuffix}", properties: m5, headers: m5 }, type: e5 }], type: f5 }, { error: "FIPS and DualStack are enabled, but this partition does not support one or both", type: d5 }], type: f5 }, { conditions: q5, rules: [{ conditions: [{ [u5]: c5, [v6]: [o5, a5] }], rules: [{ conditions: [{ [u5]: "stringEquals", [v6]: [n5, "us-gov-west-1"] }], endpoint: { url: "https://states.us-gov-west-1.amazonaws.com", properties: m5, headers: m5 }, type: e5 }, { endpoint: { url: "https://states-fips.{Region}.{PartitionResult#dnsSuffix}", properties: m5, headers: m5 }, type: e5 }], type: f5 }, { error: "FIPS is enabled but this partition does not support FIPS", type: d5 }], type: f5 }, { conditions: r5, rules: [{ conditions: [p5], rules: [{ endpoint: { url: "https://states.{Region}.{PartitionResult#dualStackDnsSuffix}", properties: m5, headers: m5 }, type: e5 }], type: f5 }, { error: "DualStack is enabled but this partition does not support DualStack", type: d5 }], type: f5 }, { endpoint: { url: "https://states.{Region}.{PartitionResult#dnsSuffix}", properties: m5, headers: m5 }, type: e5 }], type: f5 }], type: f5 }, { error: "Invalid Configuration: Missing Region", type: d5 }] };
var ruleSet5 = _data5;

// node_modules/@aws-sdk/client-sfn/dist-es/endpoint/endpointResolver.js
var cache5 = new EndpointCache({
  size: 50,
  params: ["Endpoint", "Region", "UseDualStack", "UseFIPS"]
});
var defaultEndpointResolver5 = (endpointParams, context = {}) => {
  return cache5.get(endpointParams, () => resolveEndpoint(ruleSet5, {
    endpointParams,
    logger: context.logger
  }));
};
customEndpointFunctions.aws = awsEndpointFunctions;

// node_modules/@aws-sdk/client-sfn/dist-es/runtimeConfig.shared.js
var getRuntimeConfig9 = (config) => {
  return {
    apiVersion: "2016-11-23",
    base64Decoder: config?.base64Decoder ?? fromBase64,
    base64Encoder: config?.base64Encoder ?? toBase64,
    disableHostPrefix: config?.disableHostPrefix ?? false,
    endpointProvider: config?.endpointProvider ?? defaultEndpointResolver5,
    extensions: config?.extensions ?? [],
    httpAuthSchemeProvider: config?.httpAuthSchemeProvider ?? defaultSFNHttpAuthSchemeProvider,
    httpAuthSchemes: config?.httpAuthSchemes ?? [
      {
        schemeId: "aws.auth#sigv4",
        identityProvider: (ipc) => ipc.getIdentityProvider("aws.auth#sigv4"),
        signer: new AwsSdkSigV4Signer()
      }
    ],
    logger: config?.logger ?? new NoOpLogger(),
    protocol: config?.protocol ?? AwsJson1_0Protocol,
    protocolSettings: config?.protocolSettings ?? {
      defaultNamespace: "com.amazonaws.sfn",
      xmlNamespace: "http://swf.amazonaws.com/doc/2015-07-20/",
      version: "2016-11-23",
      serviceTarget: "AWSStepFunctions"
    },
    serviceId: config?.serviceId ?? "SFN",
    urlParser: config?.urlParser ?? parseUrl,
    utf8Decoder: config?.utf8Decoder ?? fromUtf8,
    utf8Encoder: config?.utf8Encoder ?? toUtf8
  };
};

// node_modules/@aws-sdk/client-sfn/dist-es/runtimeConfig.js
var getRuntimeConfig10 = (config) => {
  emitWarningIfUnsupportedVersion2(process.version);
  const defaultsMode = resolveDefaultsModeConfig(config);
  const defaultConfigProvider = () => defaultsMode().then(loadConfigsForDefaultMode);
  const clientSharedValues = getRuntimeConfig9(config);
  emitWarningIfUnsupportedVersion(process.version);
  const loaderConfig = {
    profile: config?.profile,
    logger: clientSharedValues.logger
  };
  return {
    ...clientSharedValues,
    ...config,
    runtime: "node",
    defaultsMode,
    authSchemePreference: config?.authSchemePreference ?? loadConfig(NODE_AUTH_SCHEME_PREFERENCE_OPTIONS, loaderConfig),
    bodyLengthChecker: config?.bodyLengthChecker ?? calculateBodyLength,
    credentialDefaultProvider: config?.credentialDefaultProvider ?? defaultProvider,
    defaultUserAgentProvider: config?.defaultUserAgentProvider ?? createDefaultUserAgentProvider({ serviceId: clientSharedValues.serviceId, clientVersion: package_default.version }),
    maxAttempts: config?.maxAttempts ?? loadConfig(NODE_MAX_ATTEMPT_CONFIG_OPTIONS, config),
    region: config?.region ?? loadConfig(NODE_REGION_CONFIG_OPTIONS, { ...NODE_REGION_CONFIG_FILE_OPTIONS, ...loaderConfig }),
    requestHandler: NodeHttpHandler.create(config?.requestHandler ?? defaultConfigProvider),
    retryMode: config?.retryMode ?? loadConfig({
      ...NODE_RETRY_MODE_CONFIG_OPTIONS,
      default: async () => (await defaultConfigProvider()).retryMode || DEFAULT_RETRY_MODE
    }, config),
    sha256: config?.sha256 ?? Hash.bind(null, "sha256"),
    streamCollector: config?.streamCollector ?? streamCollector,
    useDualstackEndpoint: config?.useDualstackEndpoint ?? loadConfig(NODE_USE_DUALSTACK_ENDPOINT_CONFIG_OPTIONS, loaderConfig),
    useFipsEndpoint: config?.useFipsEndpoint ?? loadConfig(NODE_USE_FIPS_ENDPOINT_CONFIG_OPTIONS, loaderConfig),
    userAgentAppId: config?.userAgentAppId ?? loadConfig(NODE_APP_ID_CONFIG_OPTIONS, loaderConfig)
  };
};

// node_modules/@aws-sdk/client-sfn/dist-es/runtimeExtensions.js
init_dist_es47();
init_dist_es2();
init_dist_es27();

// node_modules/@aws-sdk/client-sfn/dist-es/auth/httpAuthExtensionConfiguration.js
var getHttpAuthExtensionConfiguration5 = (runtimeConfig) => {
  const _httpAuthSchemes = runtimeConfig.httpAuthSchemes;
  let _httpAuthSchemeProvider = runtimeConfig.httpAuthSchemeProvider;
  let _credentials = runtimeConfig.credentials;
  return {
    setHttpAuthScheme(httpAuthScheme) {
      const index = _httpAuthSchemes.findIndex((scheme) => scheme.schemeId === httpAuthScheme.schemeId);
      if (index === -1) {
        _httpAuthSchemes.push(httpAuthScheme);
      } else {
        _httpAuthSchemes.splice(index, 1, httpAuthScheme);
      }
    },
    httpAuthSchemes() {
      return _httpAuthSchemes;
    },
    setHttpAuthSchemeProvider(httpAuthSchemeProvider) {
      _httpAuthSchemeProvider = httpAuthSchemeProvider;
    },
    httpAuthSchemeProvider() {
      return _httpAuthSchemeProvider;
    },
    setCredentials(credentials) {
      _credentials = credentials;
    },
    credentials() {
      return _credentials;
    }
  };
};
var resolveHttpAuthRuntimeConfig5 = (config) => {
  return {
    httpAuthSchemes: config.httpAuthSchemes(),
    httpAuthSchemeProvider: config.httpAuthSchemeProvider(),
    credentials: config.credentials()
  };
};

// node_modules/@aws-sdk/client-sfn/dist-es/runtimeExtensions.js
var resolveRuntimeExtensions5 = (runtimeConfig, extensions) => {
  const extensionConfiguration = Object.assign(getAwsRegionExtensionConfiguration(runtimeConfig), getDefaultExtensionConfiguration(runtimeConfig), getHttpHandlerExtensionConfiguration(runtimeConfig), getHttpAuthExtensionConfiguration5(runtimeConfig));
  extensions.forEach((extension) => extension.configure(extensionConfiguration));
  return Object.assign(runtimeConfig, resolveAwsRegionExtensionConfiguration(extensionConfiguration), resolveDefaultRuntimeConfig(extensionConfiguration), resolveHttpHandlerRuntimeConfig(extensionConfiguration), resolveHttpAuthRuntimeConfig5(extensionConfiguration));
};

// node_modules/@aws-sdk/client-sfn/dist-es/SFNClient.js
var SFNClient = class extends Client {
  config;
  constructor(...[configuration]) {
    const _config_0 = getRuntimeConfig10(configuration || {});
    super(_config_0);
    this.initConfig = _config_0;
    const _config_1 = resolveClientEndpointParameters(_config_0);
    const _config_2 = resolveUserAgentConfig(_config_1);
    const _config_3 = resolveRetryConfig(_config_2);
    const _config_4 = resolveRegionConfig(_config_3);
    const _config_5 = resolveHostHeaderConfig(_config_4);
    const _config_6 = resolveEndpointConfig(_config_5);
    const _config_7 = resolveHttpAuthSchemeConfig(_config_6);
    const _config_8 = resolveRuntimeExtensions5(_config_7, configuration?.extensions || []);
    this.config = _config_8;
    this.middlewareStack.use(getSchemaSerdePlugin(this.config));
    this.middlewareStack.use(getUserAgentPlugin(this.config));
    this.middlewareStack.use(getRetryPlugin(this.config));
    this.middlewareStack.use(getContentLengthPlugin(this.config));
    this.middlewareStack.use(getHostHeaderPlugin(this.config));
    this.middlewareStack.use(getLoggerPlugin(this.config));
    this.middlewareStack.use(getRecursionDetectionPlugin(this.config));
    this.middlewareStack.use(getHttpAuthSchemeEndpointRuleSetPlugin(this.config, {
      httpAuthSchemeParametersProvider: defaultSFNHttpAuthSchemeParametersProvider,
      identityProviderConfigProvider: async (config) => new DefaultIdentityProviderConfig({
        "aws.auth#sigv4": config.credentials
      })
    }));
    this.middlewareStack.use(getHttpSigningPlugin(this.config));
  }
  destroy() {
    super.destroy();
  }
};

// node_modules/@aws-sdk/client-sfn/dist-es/schemas/schemas_0.js
init_schema2();

// node_modules/@aws-sdk/client-sfn/dist-es/models/SFNServiceException.js
init_dist_es27();
var SFNServiceException = class _SFNServiceException extends ServiceException {
  constructor(options) {
    super(options);
    Object.setPrototypeOf(this, _SFNServiceException.prototype);
  }
};

// node_modules/@aws-sdk/client-sfn/dist-es/models/errors.js
var ActivityAlreadyExists = class _ActivityAlreadyExists extends SFNServiceException {
  name = "ActivityAlreadyExists";
  $fault = "client";
  constructor(opts) {
    super({
      name: "ActivityAlreadyExists",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _ActivityAlreadyExists.prototype);
  }
};
var ActivityDoesNotExist = class _ActivityDoesNotExist extends SFNServiceException {
  name = "ActivityDoesNotExist";
  $fault = "client";
  constructor(opts) {
    super({
      name: "ActivityDoesNotExist",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _ActivityDoesNotExist.prototype);
  }
};
var ActivityLimitExceeded = class _ActivityLimitExceeded extends SFNServiceException {
  name = "ActivityLimitExceeded";
  $fault = "client";
  constructor(opts) {
    super({
      name: "ActivityLimitExceeded",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _ActivityLimitExceeded.prototype);
  }
};
var ActivityWorkerLimitExceeded = class _ActivityWorkerLimitExceeded extends SFNServiceException {
  name = "ActivityWorkerLimitExceeded";
  $fault = "client";
  constructor(opts) {
    super({
      name: "ActivityWorkerLimitExceeded",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _ActivityWorkerLimitExceeded.prototype);
  }
};
var InvalidEncryptionConfiguration = class _InvalidEncryptionConfiguration extends SFNServiceException {
  name = "InvalidEncryptionConfiguration";
  $fault = "client";
  constructor(opts) {
    super({
      name: "InvalidEncryptionConfiguration",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _InvalidEncryptionConfiguration.prototype);
  }
};
var InvalidName = class _InvalidName extends SFNServiceException {
  name = "InvalidName";
  $fault = "client";
  constructor(opts) {
    super({
      name: "InvalidName",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _InvalidName.prototype);
  }
};
var KmsAccessDeniedException = class _KmsAccessDeniedException extends SFNServiceException {
  name = "KmsAccessDeniedException";
  $fault = "client";
  constructor(opts) {
    super({
      name: "KmsAccessDeniedException",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _KmsAccessDeniedException.prototype);
  }
};
var KmsThrottlingException = class _KmsThrottlingException extends SFNServiceException {
  name = "KmsThrottlingException";
  $fault = "client";
  constructor(opts) {
    super({
      name: "KmsThrottlingException",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _KmsThrottlingException.prototype);
  }
};
var TooManyTags = class _TooManyTags extends SFNServiceException {
  name = "TooManyTags";
  $fault = "client";
  resourceName;
  constructor(opts) {
    super({
      name: "TooManyTags",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _TooManyTags.prototype);
    this.resourceName = opts.resourceName;
  }
};
var ConflictException = class _ConflictException extends SFNServiceException {
  name = "ConflictException";
  $fault = "client";
  constructor(opts) {
    super({
      name: "ConflictException",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _ConflictException.prototype);
  }
};
var InvalidArn = class _InvalidArn extends SFNServiceException {
  name = "InvalidArn";
  $fault = "client";
  constructor(opts) {
    super({
      name: "InvalidArn",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _InvalidArn.prototype);
  }
};
var InvalidDefinition = class _InvalidDefinition extends SFNServiceException {
  name = "InvalidDefinition";
  $fault = "client";
  constructor(opts) {
    super({
      name: "InvalidDefinition",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _InvalidDefinition.prototype);
  }
};
var InvalidLoggingConfiguration = class _InvalidLoggingConfiguration extends SFNServiceException {
  name = "InvalidLoggingConfiguration";
  $fault = "client";
  constructor(opts) {
    super({
      name: "InvalidLoggingConfiguration",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _InvalidLoggingConfiguration.prototype);
  }
};
var InvalidTracingConfiguration = class _InvalidTracingConfiguration extends SFNServiceException {
  name = "InvalidTracingConfiguration";
  $fault = "client";
  constructor(opts) {
    super({
      name: "InvalidTracingConfiguration",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _InvalidTracingConfiguration.prototype);
  }
};
var StateMachineAlreadyExists = class _StateMachineAlreadyExists extends SFNServiceException {
  name = "StateMachineAlreadyExists";
  $fault = "client";
  constructor(opts) {
    super({
      name: "StateMachineAlreadyExists",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _StateMachineAlreadyExists.prototype);
  }
};
var StateMachineDeleting = class _StateMachineDeleting extends SFNServiceException {
  name = "StateMachineDeleting";
  $fault = "client";
  constructor(opts) {
    super({
      name: "StateMachineDeleting",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _StateMachineDeleting.prototype);
  }
};
var StateMachineLimitExceeded = class _StateMachineLimitExceeded extends SFNServiceException {
  name = "StateMachineLimitExceeded";
  $fault = "client";
  constructor(opts) {
    super({
      name: "StateMachineLimitExceeded",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _StateMachineLimitExceeded.prototype);
  }
};
var StateMachineTypeNotSupported = class _StateMachineTypeNotSupported extends SFNServiceException {
  name = "StateMachineTypeNotSupported";
  $fault = "client";
  constructor(opts) {
    super({
      name: "StateMachineTypeNotSupported",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _StateMachineTypeNotSupported.prototype);
  }
};
var ValidationException2 = class _ValidationException extends SFNServiceException {
  name = "ValidationException";
  $fault = "client";
  reason;
  constructor(opts) {
    super({
      name: "ValidationException",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _ValidationException.prototype);
    this.reason = opts.reason;
  }
};
var ResourceNotFound = class _ResourceNotFound extends SFNServiceException {
  name = "ResourceNotFound";
  $fault = "client";
  resourceName;
  constructor(opts) {
    super({
      name: "ResourceNotFound",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _ResourceNotFound.prototype);
    this.resourceName = opts.resourceName;
  }
};
var ServiceQuotaExceededException = class _ServiceQuotaExceededException extends SFNServiceException {
  name = "ServiceQuotaExceededException";
  $fault = "client";
  constructor(opts) {
    super({
      name: "ServiceQuotaExceededException",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _ServiceQuotaExceededException.prototype);
  }
};
var ExecutionDoesNotExist = class _ExecutionDoesNotExist extends SFNServiceException {
  name = "ExecutionDoesNotExist";
  $fault = "client";
  constructor(opts) {
    super({
      name: "ExecutionDoesNotExist",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _ExecutionDoesNotExist.prototype);
  }
};
var KmsInvalidStateException = class _KmsInvalidStateException extends SFNServiceException {
  name = "KmsInvalidStateException";
  $fault = "client";
  kmsKeyState;
  constructor(opts) {
    super({
      name: "KmsInvalidStateException",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _KmsInvalidStateException.prototype);
    this.kmsKeyState = opts.kmsKeyState;
  }
};
var StateMachineDoesNotExist = class _StateMachineDoesNotExist extends SFNServiceException {
  name = "StateMachineDoesNotExist";
  $fault = "client";
  constructor(opts) {
    super({
      name: "StateMachineDoesNotExist",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _StateMachineDoesNotExist.prototype);
  }
};
var InvalidToken = class _InvalidToken extends SFNServiceException {
  name = "InvalidToken";
  $fault = "client";
  constructor(opts) {
    super({
      name: "InvalidToken",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _InvalidToken.prototype);
  }
};
var ExecutionLimitExceeded = class _ExecutionLimitExceeded extends SFNServiceException {
  name = "ExecutionLimitExceeded";
  $fault = "client";
  constructor(opts) {
    super({
      name: "ExecutionLimitExceeded",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _ExecutionLimitExceeded.prototype);
  }
};
var ExecutionNotRedrivable = class _ExecutionNotRedrivable extends SFNServiceException {
  name = "ExecutionNotRedrivable";
  $fault = "client";
  constructor(opts) {
    super({
      name: "ExecutionNotRedrivable",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _ExecutionNotRedrivable.prototype);
  }
};
var TaskDoesNotExist = class _TaskDoesNotExist extends SFNServiceException {
  name = "TaskDoesNotExist";
  $fault = "client";
  constructor(opts) {
    super({
      name: "TaskDoesNotExist",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _TaskDoesNotExist.prototype);
  }
};
var TaskTimedOut = class _TaskTimedOut extends SFNServiceException {
  name = "TaskTimedOut";
  $fault = "client";
  constructor(opts) {
    super({
      name: "TaskTimedOut",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _TaskTimedOut.prototype);
  }
};
var InvalidOutput = class _InvalidOutput extends SFNServiceException {
  name = "InvalidOutput";
  $fault = "client";
  constructor(opts) {
    super({
      name: "InvalidOutput",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _InvalidOutput.prototype);
  }
};
var ExecutionAlreadyExists = class _ExecutionAlreadyExists extends SFNServiceException {
  name = "ExecutionAlreadyExists";
  $fault = "client";
  constructor(opts) {
    super({
      name: "ExecutionAlreadyExists",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _ExecutionAlreadyExists.prototype);
  }
};
var InvalidExecutionInput = class _InvalidExecutionInput extends SFNServiceException {
  name = "InvalidExecutionInput";
  $fault = "client";
  constructor(opts) {
    super({
      name: "InvalidExecutionInput",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _InvalidExecutionInput.prototype);
  }
};
var MissingRequiredParameter = class _MissingRequiredParameter extends SFNServiceException {
  name = "MissingRequiredParameter";
  $fault = "client";
  constructor(opts) {
    super({
      name: "MissingRequiredParameter",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _MissingRequiredParameter.prototype);
  }
};

// node_modules/@aws-sdk/client-sfn/dist-es/schemas/schemas_0.js
var _AAE = "ActivityAlreadyExists";
var _ADNE = "ActivityDoesNotExist";
var _ALE = "ActivityLimitExceeded";
var _AWLE = "ActivityWorkerLimitExceeded";
var _BD = "BillingDetails";
var _CE = "ConflictException";
var _CWEEDD = "CloudWatchEventsExecutionDataDetails";
var _D = "Definition";
var _EAE = "ExecutionAlreadyExists";
var _EDNE = "ExecutionDoesNotExist";
var _EHI = "ExceptionHandlerIndex";
var _ELE = "ExecutionLimitExceeded";
var _ENR = "ExecutionNotRedrivable";
var _IA = "InvalidArn";
var _ID = "InspectionData";
var _IDR = "InspectionDataRequest";
var _IDRn = "InspectionDataResponse";
var _IDn = "InvalidDefinition";
var _IEC = "InvalidEncryptionConfiguration";
var _IED = "InspectionErrorDetails";
var _IEI = "InvalidExecutionInput";
var _ILC = "InvalidLoggingConfiguration";
var _IMC = "InspectionMaxConcurrency";
var _IN = "InvalidName";
var _IO = "InvalidOutput";
var _IT2 = "InvalidToken";
var _ITC = "InvalidTracingConfiguration";
var _ITFC = "InspectionToleratedFailureCount";
var _ITFP = "InspectionToleratedFailurePercentage";
var _KADE = "KmsAccessDeniedException";
var _KISE = "KmsInvalidStateException";
var _KTE = "KmsThrottlingException";
var _MEO = "MockErrorOutput";
var _MI = "MockInput";
var _MRP = "MissingRequiredParameter";
var _RBIS = "RetryBackoffIntervalSeconds";
var _RNF = "ResourceNotFound";
var _SC = "SensitiveCause";
var _SD = "SensitiveData";
var _SE = "SensitiveError";
var _SMAE = "StateMachineAlreadyExists";
var _SMD = "StateMachineDeleting";
var _SMDNE = "StateMachineDoesNotExist";
var _SMLE = "StateMachineLimitExceeded";
var _SMTNS = "StateMachineTypeNotSupported";
var _SQEE = "ServiceQuotaExceededException";
var _SSE = "StartSyncExecution";
var _SSEI = "StartSyncExecutionInput";
var _SSEO = "StartSyncExecutionOutput";
var _STF = "SendTaskFailure";
var _STFI = "SendTaskFailureInput";
var _STFO = "SendTaskFailureOutput";
var _STS = "SendTaskSuccess";
var _STSI = "SendTaskSuccessInput";
var _STSO = "SendTaskSuccessOutput";
var _TDNE = "TaskDoesNotExist";
var _TMT = "TooManyTags";
var _TS = "TestState";
var _TSC = "TestStateConfiguration";
var _TSI = "TestStateInput";
var _TSO = "TestStateOutput";
var _TSSN = "TestStateStateName";
var _TTO = "TaskTimedOut";
var _URI = "UntagResourceInput";
var _VE2 = "ValidationException";
var _aAf = "afterArguments";
var _aIB = "afterItemBatcher";
var _aIP = "afterInputPath";
var _aIPf = "afterItemsPath";
var _aIPft = "afterItemsPointer";
var _aIS = "afterItemSelector";
var _aP = "afterParameters";
var _aRP = "afterResultPath";
var _aRS = "afterResultSelector";
var _b = "body";
var _bD = "billingDetails";
var _bDIM = "billedDurationInMilliseconds";
var _bMUIMB = "billedMemoryUsedInMB";
var _c5 = "client";
var _cI3 = "catchIndex";
var _ca = "cause";
var _co3 = "context";
var _de = "definition";
var _e5 = "error";
var _eA2 = "executionArn";
var _eCBS = "errorCausedByState";
var _eD = "errorDetails";
var _eO = "errorOutput";
var _end = "endpoint";
var _fVM = "fieldValidationMode";
var _h4 = "headers";
var _hE5 = "httpError";
var _i = "input";
var _iD = "inputDetails";
var _iDn = "includedData";
var _iDns = "inspectionData";
var _iL = "inspectionLevel";
var _in = "included";
var _kKS = "kmsKeyState";
var _m4 = "message";
var _mC = "maxConcurrency";
var _mIFC = "mapIterationFailureCount";
var _mIRD = "mapItemReaderData";
var _me = "method";
var _mo = "mock";
var _n = "name";
var _nS = "nextState";
var _o = "output";
var _oD = "outputDetails";
var _pr = "protocol";
var _rA = "roleArn";
var _rAe = "resourceArn";
var _rBIS = "retryBackoffIntervalSeconds";
var _rIe = "retryIndex";
var _rN2 = "resourceName";
var _rRC = "retrierRetryCount";
var _rSe = "revealSecrets";
var _re = "result";
var _rea = "reason";
var _req = "request";
var _res = "response";
var _s5 = "status";
var _sC = "statusCode";
var _sCt = "stateConfiguration";
var _sD = "startDate";
var _sDt = "stopDate";
var _sM = "statusMessage";
var _sMA = "stateMachineArn";
var _sN = "stateName";
var _sm3 = "smithy.ts.sdk.synthetic.com.amazonaws.sfn";
var _tFC = "toleratedFailureCount";
var _tFP = "toleratedFailurePercentage";
var _tH = "traceHeader";
var _tK = "tagKeys";
var _tT3 = "taskToken";
var _u = "url";
var _v = "variables";
var n05 = "com.amazonaws.sfn";
var Definition = [0, n05, _D, 8, 0];
var ExceptionHandlerIndex = [0, n05, _EHI, 8, 1];
var InspectionMaxConcurrency = [0, n05, _IMC, 8, 1];
var InspectionToleratedFailureCount = [0, n05, _ITFC, 8, 1];
var InspectionToleratedFailurePercentage = [0, n05, _ITFP, 8, 1];
var RetryBackoffIntervalSeconds = [0, n05, _RBIS, 8, 1];
var SensitiveCause = [0, n05, _SC, 8, 0];
var SensitiveData = [0, n05, _SD, 8, 0];
var SensitiveError = [0, n05, _SE, 8, 0];
var TestStateStateName = [0, n05, _TSSN, 8, 0];
var ActivityAlreadyExists$ = [-3, n05, _AAE, { [_e5]: _c5 }, [_m4], [0]];
TypeRegistry.for(n05).registerError(ActivityAlreadyExists$, ActivityAlreadyExists);
var ActivityDoesNotExist$ = [-3, n05, _ADNE, { [_e5]: _c5 }, [_m4], [0]];
TypeRegistry.for(n05).registerError(ActivityDoesNotExist$, ActivityDoesNotExist);
var ActivityLimitExceeded$ = [-3, n05, _ALE, { [_e5]: _c5 }, [_m4], [0]];
TypeRegistry.for(n05).registerError(ActivityLimitExceeded$, ActivityLimitExceeded);
var ActivityWorkerLimitExceeded$ = [-3, n05, _AWLE, { [_e5]: _c5 }, [_m4], [0]];
TypeRegistry.for(n05).registerError(ActivityWorkerLimitExceeded$, ActivityWorkerLimitExceeded);
var BillingDetails$ = [3, n05, _BD, 0, [_bMUIMB, _bDIM], [1, 1]];
var CloudWatchEventsExecutionDataDetails$ = [3, n05, _CWEEDD, 0, [_in], [2]];
var ConflictException$ = [-3, n05, _CE, { [_e5]: _c5, [_hE5]: 409 }, [_m4], [0]];
TypeRegistry.for(n05).registerError(ConflictException$, ConflictException);
var ExecutionAlreadyExists$ = [-3, n05, _EAE, { [_e5]: _c5 }, [_m4], [0]];
TypeRegistry.for(n05).registerError(ExecutionAlreadyExists$, ExecutionAlreadyExists);
var ExecutionDoesNotExist$ = [-3, n05, _EDNE, { [_e5]: _c5 }, [_m4], [0]];
TypeRegistry.for(n05).registerError(ExecutionDoesNotExist$, ExecutionDoesNotExist);
var ExecutionLimitExceeded$ = [-3, n05, _ELE, { [_e5]: _c5 }, [_m4], [0]];
TypeRegistry.for(n05).registerError(ExecutionLimitExceeded$, ExecutionLimitExceeded);
var ExecutionNotRedrivable$ = [-3, n05, _ENR, { [_e5]: _c5 }, [_m4], [0]];
TypeRegistry.for(n05).registerError(ExecutionNotRedrivable$, ExecutionNotRedrivable);
var InspectionData$ = [
  3,
  n05,
  _ID,
  8,
  [_i, _aAf, _aIP, _aP, _re, _aRS, _aRP, _req, _res, _v, _eD, _aIPf, _aIS, _aIB, _aIPft, _tFC, _tFP, _mC],
  [
    [() => SensitiveData, 0],
    [() => SensitiveData, 0],
    [() => SensitiveData, 0],
    [() => SensitiveData, 0],
    [() => SensitiveData, 0],
    [() => SensitiveData, 0],
    [() => SensitiveData, 0],
    () => InspectionDataRequest$,
    () => InspectionDataResponse$,
    [() => SensitiveData, 0],
    [() => InspectionErrorDetails$, 0],
    [() => SensitiveData, 0],
    [() => SensitiveData, 0],
    [() => SensitiveData, 0],
    [() => SensitiveData, 0],
    [() => InspectionToleratedFailureCount, 0],
    [() => InspectionToleratedFailurePercentage, 0],
    [() => InspectionMaxConcurrency, 0]
  ]
];
var InspectionDataRequest$ = [3, n05, _IDR, 0, [_pr, _me, _u, _h4, _b], [0, 0, 0, 0, 0]];
var InspectionDataResponse$ = [3, n05, _IDRn, 0, [_pr, _sC, _sM, _h4, _b], [0, 0, 0, 0, 0]];
var InspectionErrorDetails$ = [
  3,
  n05,
  _IED,
  0,
  [_cI3, _rIe, _rBIS],
  [
    [() => ExceptionHandlerIndex, 0],
    [() => ExceptionHandlerIndex, 0],
    [() => RetryBackoffIntervalSeconds, 0]
  ]
];
var InvalidArn$ = [-3, n05, _IA, { [_e5]: _c5 }, [_m4], [0]];
TypeRegistry.for(n05).registerError(InvalidArn$, InvalidArn);
var InvalidDefinition$ = [-3, n05, _IDn, { [_e5]: _c5 }, [_m4], [0]];
TypeRegistry.for(n05).registerError(InvalidDefinition$, InvalidDefinition);
var InvalidEncryptionConfiguration$ = [-3, n05, _IEC, { [_e5]: _c5 }, [_m4], [0]];
TypeRegistry.for(n05).registerError(InvalidEncryptionConfiguration$, InvalidEncryptionConfiguration);
var InvalidExecutionInput$ = [-3, n05, _IEI, { [_e5]: _c5 }, [_m4], [0]];
TypeRegistry.for(n05).registerError(InvalidExecutionInput$, InvalidExecutionInput);
var InvalidLoggingConfiguration$ = [-3, n05, _ILC, { [_e5]: _c5 }, [_m4], [0]];
TypeRegistry.for(n05).registerError(InvalidLoggingConfiguration$, InvalidLoggingConfiguration);
var InvalidName$ = [-3, n05, _IN, { [_e5]: _c5 }, [_m4], [0]];
TypeRegistry.for(n05).registerError(InvalidName$, InvalidName);
var InvalidOutput$ = [-3, n05, _IO, { [_e5]: _c5 }, [_m4], [0]];
TypeRegistry.for(n05).registerError(InvalidOutput$, InvalidOutput);
var InvalidToken$ = [-3, n05, _IT2, { [_e5]: _c5 }, [_m4], [0]];
TypeRegistry.for(n05).registerError(InvalidToken$, InvalidToken);
var InvalidTracingConfiguration$ = [-3, n05, _ITC, { [_e5]: _c5 }, [_m4], [0]];
TypeRegistry.for(n05).registerError(InvalidTracingConfiguration$, InvalidTracingConfiguration);
var KmsAccessDeniedException$ = [-3, n05, _KADE, { [_e5]: _c5 }, [_m4], [0]];
TypeRegistry.for(n05).registerError(KmsAccessDeniedException$, KmsAccessDeniedException);
var KmsInvalidStateException$ = [-3, n05, _KISE, { [_e5]: _c5 }, [_kKS, _m4], [0, 0]];
TypeRegistry.for(n05).registerError(KmsInvalidStateException$, KmsInvalidStateException);
var KmsThrottlingException$ = [-3, n05, _KTE, { [_e5]: _c5 }, [_m4], [0]];
TypeRegistry.for(n05).registerError(KmsThrottlingException$, KmsThrottlingException);
var MissingRequiredParameter$ = [-3, n05, _MRP, { [_e5]: _c5 }, [_m4], [0]];
TypeRegistry.for(n05).registerError(MissingRequiredParameter$, MissingRequiredParameter);
var MockErrorOutput$ = [
  3,
  n05,
  _MEO,
  0,
  [_e5, _ca],
  [
    [() => SensitiveError, 0],
    [() => SensitiveCause, 0]
  ]
];
var MockInput$ = [
  3,
  n05,
  _MI,
  0,
  [_re, _eO, _fVM],
  [[() => SensitiveData, 0], [() => MockErrorOutput$, 0], 0]
];
var ResourceNotFound$ = [-3, n05, _RNF, { [_e5]: _c5, [_hE5]: 404 }, [_m4, _rN2], [0, 0]];
TypeRegistry.for(n05).registerError(ResourceNotFound$, ResourceNotFound);
var SendTaskFailureInput$ = [
  3,
  n05,
  _STFI,
  0,
  [_tT3, _e5, _ca],
  [0, [() => SensitiveError, 0], [() => SensitiveCause, 0]]
];
var SendTaskFailureOutput$ = [3, n05, _STFO, 0, [], []];
var SendTaskSuccessInput$ = [3, n05, _STSI, 0, [_tT3, _o], [0, [() => SensitiveData, 0]]];
var SendTaskSuccessOutput$ = [3, n05, _STSO, 0, [], []];
var ServiceQuotaExceededException$ = [-3, n05, _SQEE, { [_e5]: _c5, [_hE5]: 402 }, [_m4], [0]];
TypeRegistry.for(n05).registerError(ServiceQuotaExceededException$, ServiceQuotaExceededException);
var StartSyncExecutionInput$ = [
  3,
  n05,
  _SSEI,
  0,
  [_sMA, _n, _i, _tH, _iDn],
  [0, 0, [() => SensitiveData, 0], 0, 0]
];
var StartSyncExecutionOutput$ = [
  3,
  n05,
  _SSEO,
  0,
  [_eA2, _sMA, _n, _sD, _sDt, _s5, _e5, _ca, _i, _iD, _o, _oD, _tH, _bD],
  [
    0,
    0,
    0,
    4,
    4,
    0,
    [() => SensitiveError, 0],
    [() => SensitiveCause, 0],
    [() => SensitiveData, 0],
    () => CloudWatchEventsExecutionDataDetails$,
    [() => SensitiveData, 0],
    () => CloudWatchEventsExecutionDataDetails$,
    0,
    () => BillingDetails$
  ]
];
var StateMachineAlreadyExists$ = [-3, n05, _SMAE, { [_e5]: _c5 }, [_m4], [0]];
TypeRegistry.for(n05).registerError(StateMachineAlreadyExists$, StateMachineAlreadyExists);
var StateMachineDeleting$ = [-3, n05, _SMD, { [_e5]: _c5 }, [_m4], [0]];
TypeRegistry.for(n05).registerError(StateMachineDeleting$, StateMachineDeleting);
var StateMachineDoesNotExist$ = [-3, n05, _SMDNE, { [_e5]: _c5 }, [_m4], [0]];
TypeRegistry.for(n05).registerError(StateMachineDoesNotExist$, StateMachineDoesNotExist);
var StateMachineLimitExceeded$ = [-3, n05, _SMLE, { [_e5]: _c5 }, [_m4], [0]];
TypeRegistry.for(n05).registerError(StateMachineLimitExceeded$, StateMachineLimitExceeded);
var StateMachineTypeNotSupported$ = [-3, n05, _SMTNS, { [_e5]: _c5 }, [_m4], [0]];
TypeRegistry.for(n05).registerError(StateMachineTypeNotSupported$, StateMachineTypeNotSupported);
var TaskDoesNotExist$ = [-3, n05, _TDNE, { [_e5]: _c5 }, [_m4], [0]];
TypeRegistry.for(n05).registerError(TaskDoesNotExist$, TaskDoesNotExist);
var TaskTimedOut$ = [-3, n05, _TTO, { [_e5]: _c5 }, [_m4], [0]];
TypeRegistry.for(n05).registerError(TaskTimedOut$, TaskTimedOut);
var TestStateConfiguration$ = [
  3,
  n05,
  _TSC,
  0,
  [_rRC, _eCBS, _mIFC, _mIRD],
  [1, [() => TestStateStateName, 0], 1, [() => SensitiveData, 0]]
];
var TestStateInput$ = [
  3,
  n05,
  _TSI,
  0,
  [_de, _rA, _i, _iL, _rSe, _v, _sN, _mo, _co3, _sCt],
  [
    [() => Definition, 0],
    0,
    [() => SensitiveData, 0],
    0,
    2,
    [() => SensitiveData, 0],
    [() => TestStateStateName, 0],
    [() => MockInput$, 0],
    [() => SensitiveData, 0],
    [() => TestStateConfiguration$, 0]
  ]
];
var TestStateOutput$ = [
  3,
  n05,
  _TSO,
  0,
  [_o, _e5, _ca, _iDns, _nS, _s5],
  [[() => SensitiveData, 0], [() => SensitiveError, 0], [() => SensitiveCause, 0], [() => InspectionData$, 0], 0, 0]
];
var TooManyTags$ = [-3, n05, _TMT, { [_e5]: _c5, [_hE5]: 400 }, [_m4, _rN2], [0, 0]];
TypeRegistry.for(n05).registerError(TooManyTags$, TooManyTags);
var UntagResourceInput$ = [3, n05, _URI, 0, [_rAe, _tK], [0, 64 | 0]];
var ValidationException$2 = [-3, n05, _VE2, { [_e5]: _c5, [_hE5]: 400 }, [_m4, _rea], [0, 0]];
TypeRegistry.for(n05).registerError(ValidationException$2, ValidationException2);
var SFNServiceException$ = [-3, _sm3, "SFNServiceException", 0, [], []];
TypeRegistry.for(_sm3).registerError(SFNServiceException$, SFNServiceException);
var TagKeyList = 64 | 0;
var SendTaskFailure$ = [
  9,
  n05,
  _STF,
  0,
  () => SendTaskFailureInput$,
  () => SendTaskFailureOutput$
];
var SendTaskSuccess$ = [
  9,
  n05,
  _STS,
  0,
  () => SendTaskSuccessInput$,
  () => SendTaskSuccessOutput$
];
var StartSyncExecution$ = [
  9,
  n05,
  _SSE,
  { [_end]: ["sync-"] },
  () => StartSyncExecutionInput$,
  () => StartSyncExecutionOutput$
];
var TestState$ = [
  9,
  n05,
  _TS,
  { [_end]: ["sync-"] },
  () => TestStateInput$,
  () => TestStateOutput$
];

// node_modules/@aws-sdk/client-sfn/dist-es/commands/SendTaskFailureCommand.js
init_dist_es36();
init_dist_es27();
var SendTaskFailureCommand = class extends Command.classBuilder().ep(commonParams).m(function(Command2, cs, config, o6) {
  return [getEndpointPlugin(config, Command2.getEndpointParameterInstructions())];
}).s("AWSStepFunctions", "SendTaskFailure", {}).n("SFNClient", "SendTaskFailureCommand").sc(SendTaskFailure$).build() {
};

// node_modules/@aws-sdk/client-sfn/dist-es/commands/SendTaskSuccessCommand.js
init_dist_es36();
init_dist_es27();
var SendTaskSuccessCommand = class extends Command.classBuilder().ep(commonParams).m(function(Command2, cs, config, o6) {
  return [getEndpointPlugin(config, Command2.getEndpointParameterInstructions())];
}).s("AWSStepFunctions", "SendTaskSuccess", {}).n("SFNClient", "SendTaskSuccessCommand").sc(SendTaskSuccess$).build() {
};

// lambdas/shared/token-handler.ts
var sfn = new SFNClient({});
var ddb = new DynamoDBClient({});
var handler = async (event) => {
  console.log(event);
  const payload = typeof event.body === "string" ? JSON.parse(event.body) : event.body;
  const { email, token, code } = payload;
  if (!token || !code) {
    return { statusCode: 400, body: JSON.stringify({ error: "token and code required" }) };
  }
  const stored = await ddb.send(
    new GetItemCommand({
      TableName: process.env.TABLE_NAME,
      Key: { id: { S: email }, sort: { S: code } }
    })
  );
  console.log("taskToken GetItemCommand", stored);
  const expectedCode = stored.Item?.sort?.S;
  if (expectedCode !== code) {
    if (!event.body.durable) {
      await sfn.send(new SendTaskFailureCommand({
        taskToken: token,
        cause: "Invalid verification code"
      }));
    }
    return { statusCode: 400, body: JSON.stringify({ error: "Invalid verification code" }) };
  }
  if (payload.durable) {
    console.log("Is a durable handler invocation");
    const client = new LambdaClient();
    const command = new SendDurableExecutionCallbackSuccessCommand({
      CallbackId: token,
      Result: JSON.stringify({
        verification: "ok"
      })
    });
    await client.send(
      command
    );
  } else {
    const cmd = new SendTaskSuccessCommand({
      taskToken: token,
      output: JSON.stringify({ verification: "ok" })
      // any payload you want the state machine to receive
    });
    const result = await sfn.send(cmd);
    console.log("taskToken result", result);
  }
  await ddb.send(
    new DeleteItemCommand({
      TableName: process.env.TABLE_NAME,
      Key: { id: { S: email } }
    })
  );
  return { statusCode: 200, body: JSON.stringify({ message: "Verification accepted" }) };
};
export {
  handler
};
