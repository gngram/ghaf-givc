{
  config,
  lib,
  pkgs,
  ...
}:

with lib;

let
  cfgServer = config.givc.spire-server;
  cfgAgent = config.givc.spire-agent;

  # --- SERVER CONFIG GENERATOR ---
  # --- SERVER CONFIG GENERATOR ---
  serverConf = pkgs.writeText "server.conf" ''
    server {
      bind_address = "${cfgServer.bindAddress}"
      bind_port = ${toString cfgServer.bindPort}
      trust_domain = "${cfgServer.trustDomain}"
      data_dir = "/var/lib/spire-server"
      log_level = "DEBUG"

      # FIX 1: Use the specific configuration key for X.509 SVIDs
      default_x509_svid_ttl = "1h"

      # Optional: CA TTL (Default is 24h, this sets it to 1 week)
      ca_ttl = "168h"
    }

    plugins {
      DataStore "sql" {
        plugin_data {
          database_type = "sqlite3"
          # FIX 2: Use URI format to ensure the driver handles the path correctly
          connection_string = "file:///var/lib/spire-server/datastore.sqlite3"
        }
      }

      NodeAttestor "join_token" {
        plugin_data {}
      }

      KeyManager "disk" {
        plugin_data {
          keys_path = "/var/lib/spire-server/keys.json"
        }
      }
    }
  '';

  # --- AGENT CONFIG GENERATOR ---
  agentConf = pkgs.writeText "agent.conf" ''
    agent {
      data_dir = "/var/lib/spire-agent"
      log_level = "DEBUG"
      server_address = "${cfgAgent.serverAddress}"
      server_port = ${toString cfgAgent.serverPort}
      trust_domain = "${cfgAgent.trustDomain}"

      socket_path = "/run/spire/sockets/agent.sock"

      # Allow the agent to auto-fetch the trust bundle from the server
      # use root CA certificate for verification
      insecure_bootstrap = true

      join_token = "${cfgAgent.joinToken}"
    }

    plugins {
      NodeAttestor "join_token" {
        plugin_data {}
      }
      KeyManager "disk" {
        plugin_data {
          directory = "/var/lib/spire-agent"
        }
      }
      WorkloadAttestor "unix" {
        plugin_data {
          discover_workload_path = true
        }
      }
    }
  '';

in
{
  # --- OPTIONS INTERFACE ---
  options.givc = {

    # --- SERVER OPTIONS ---
    spire-server = {
      enable = mkEnableOption "SPIRE Server";
      bindAddress = mkOption {
        type = types.str;
        default = "0.0.0.0";
      };
      bindPort = mkOption {
        type = types.int;
        default = 8081;
      };
      trustDomain = mkOption {
        type = types.str;
        default = "example.org";
      };
    };

    # --- AGENT OPTIONS ---
    spire-agent = {
      enable = mkEnableOption "SPIRE Agent";
      serverAddress = mkOption {
        type = types.str;
        description = "IP/Hostname of the SPIRE Server";
      };
      serverPort = mkOption {
        type = types.int;
        default = 8081;
      };
      trustDomain = mkOption {
        type = types.str;
        default = "example.org";
      };
      joinToken = mkOption {
        type = types.str;
        description = "Token to join the trust domain";
      };
    };
  };

  # --- IMPLEMENTATION ---
  config = mkMerge [

    # --- SERVER IMPLEMENTATION ---
    (mkIf cfgServer.enable {
      users.users.spire = {
        isSystemUser = true;
        group = "spire";
      };
      users.groups.spire = { };

      systemd.services.spire-server = {
        description = "SPIFFE SPIRE Server";
        wantedBy = [ "multi-user.target" ];
        after = [ "network.target" ];
        serviceConfig = {
          ExecStart = "${pkgs.spire-server}/bin/spire-server run -config ${serverConf}";
          User = "spire";
          Group = "spire";
          StateDirectory = "spire-server";
          WorkingDirectory = "/var/lib/spire-server";
          Restart = "always";
        };
      };
    })

    # --- AGENT IMPLEMENTATION ---
    (mkIf cfgAgent.enable {
      users.users.spire-agent = {
        isSystemUser = true;
        group = "spire-agent";
      };
      users.groups.spire-agent = { };

      # Create socket directory with correct permissions
      systemd.tmpfiles.rules = [
        "d /run/spire/sockets 0755 spire-agent spire-agent -"
      ];

      systemd.services.spire-agent = {
        description = "SPIFFE SPIRE Agent";
        wantedBy = [ "multi-user.target" ];
        after = [ "network.target" ];
        serviceConfig = {
          ExecStart = "${pkgs.spire-agent}/bin/spire-agent run -config ${agentConf}";
          User = "spire-agent";
          Group = "spire-agent";
          StateDirectory = "spire-agent";
          WorkingDirectory = "/var/lib/spire-agent";
          Restart = "always";
        };
      };
    })
  ];
}
