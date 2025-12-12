# SPDX-FileCopyrightText: 2024-2026 TII (SSRC) and the Ghaf contributors
# SPDX-License-Identifier: Apache-2.0
{ self }:
{
  config,
  pkgs,
  lib,
  ...
}:
let
  cfg = config.givc.admin;
  opacfg = cfg.policy.opa;
  updatercfg = cfg.policy.updater;
  inherit (self.packages.${pkgs.stdenv.hostPlatform.system}) givc-admin;
  inherit (lib)
    mkOption
    mkEnableOption
    mkIf
    types
    trivial
    unique
    strings
    concatStringsSep
    attrsets
    literalExpression
    ;
  inherit (import ./definitions.nix { inherit config lib; })
    transportSubmodule
    tlsSubmodule
    ;
  tcpAddresses = lib.filter (addr: addr.protocol == "tcp") cfg.addresses;
  unixAddresses = lib.filter (addr: addr.protocol == "unix") cfg.addresses;
  vsockAddresses = lib.filter (addr: addr.protocol == "vsock") cfg.addresses;
  opaServerPort = 8181;
  opaPolicyDir = "/etc/policies/data/opa";
  opaUser = "opa";

in
{
  options.givc.admin = {
    enable = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Whether to enable the GIVC admin module, which is responsible for managing the system.
        The admin module is responsible for registration, monitoring, and proxying commands across a virtualized system
        of host, system VMs, and application VMs.
      '';
    };
    debug = mkEnableOption "givc-admin debug logging. This increases the verbosity of the logs";

    name = mkOption {
      type = types.str;
      default = "localhost";
      description = ''
        Network name of the host running the admin service.
        > **Caution**
        > This is used to validate the TLS host name and must match the names used in the transport configurations (addresses).
      '';
    };

    addresses = mkOption {
      type = types.listOf transportSubmodule;
      default = [ ];
      defaultText = literalExpression ''
        addresses = [
          {
            name = "localhost";
            addr = "127.0.0.1";
            protocol = "tcp";
            port = "9000";
          }
        ];'';
      example = literalExpression ''
        addresses = [
          {
            name = "admin-vm";
            addr = "192.168.100.3";
            protocol = "tcp";
            port = "9001";
          }
          {
            name = "admin-vm";
            addr = "unix:///run/givc-admin.sock";
            protocol = "unix";
            # port is ignored
          }
        ];'';
      description = ''
        List of addresses for the admin service to listen on. Requires a list of type `transportSubmodule`.
      '';
    };

    services = mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = literalExpression ''services = ["microvm@net-vm.service"];'';
      description = ''
        List of microvm services of the system-vms for the admin module to administrate, excluding any dynamic VMs such as app-vm. Expects a space separated list.
        Must be a of type 'service', e.g., 'microvm@net-vm.service'.
      '';
    };

    tls = mkOption {
      type = tlsSubmodule;
      default = { };
      defaultText = literalExpression ''
        tls = {
          enable = true;
          caCertPath = "/etc/givc/ca-cert.pem";
          certPath = /etc/givc/cert.pem";
          keyPath = "/etc/givc/key.pem";
        };'';
      example = literalExpression ''
        tls = {
          enable = true;
          caCertPath = "/etc/ssl/certs/ca-certificates.crt";
          certPath = "/etc/ssl/certs/server.crt";
          keyPath = "/etc/ssl/private/server.key";
        };'';
      description = ''
        TLS options for gRPC connections. It is enabled by default to discourage unprotected connections,
        and requires paths to certificates and key being set. To disable it use `tls.enable = false;`.

        > **Caution**
        > It is recommended to use a global TLS flag to avoid inconsistent configurations that will result in connection errors.
      '';
    };

    policy = {
      opa = {
        enable = mkEnableOption "Start open policy agent service.";
      };
      url = mkOption {
        type = types.str;
        description = "URL of policy store";
      };
      rev = mkOption {
        type = types.str;
        description = "Rev of the default policy";
      };
      sha256 = mkOption {
        type = types.str;
        description = "SHA of the default policy";
      };
      updater = {
        enable = mkEnableOption "Enable policy updater.";
        ref = mkOption {
          type = types.str;
          description = "Tip(branch) of policy store to monitor for update. Default Rev must be predecessor of this.";
          default = "main";
        };
        interval = mkOption {
          type = types.int;
          default = 0;
          description = "Interval of policy update check in seconds. 0 means once a day.";
        };
      };
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion =
          !(cfg.tls.enable && (cfg.tls.caCertPath == "" || cfg.tls.certPath == "" || cfg.tls.keyPath == ""));
        message = "The TLS option requires paths' to CA certificate, service certificate, and service key.";
      }
    ];

    users.users."${opaUser}" = mkIf opacfg.enable {
      isSystemUser = true;
      group = opaUser;
    };
    users.groups."${opaUser}" = mkIf opacfg.enable { };

    systemd.services.open-policy-agent = mkIf opacfg.enable {
      description = "Open Policy Agent";
      serviceConfig = {
        Type = "simple";
        User = "${opaUser}";
        Group = "${opaUser}";
        ExecStart = ''
          ${pkgs.open-policy-agent}/bin/opa run \
            --server \
            --addr localhost:${toString opaServerPort} \
            --watch ${opaPolicyDir} \
        '';
        Restart = "always";
      };
    };

    systemd.paths.open-policy-agent = mkIf opacfg.enable {
      description = "Watch policy directory directory";
      pathConfig = {
        PathExists = "${opaPolicyDir}";
      };
      wantedBy = [ "multi-user.target" ];
    };

    systemd.services.givc-admin =
      let
        args = concatStringsSep " " (
          (map (addr: "--listen ${addr.addr}:${addr.port}") tcpAddresses)
          ++ (map (addr: "--listen ${addr.addr}") unixAddresses)
          ++ (map (addr: "--listen vsock:${addr.addr}:${addr.port}") vsockAddresses)
        );

        defaultPolicySrc = pkgs.fetchgit {
          inherit (cfg.policy) url;
          inherit (cfg.policy) rev;
          inherit (cfg.policy) sha256;
          leaveDotGit = true;
        };

        preStartScript = pkgs.writeScript "policy_init" ''
          #!${pkgs.bash}/bin/bash
          policyDir=/etc/policies
          if [ ! -d "$policyDir" ]; then
            install -d -m 0755 -o root -g root "$policyDir/.cache"
          fi
          if [ ! -d "$policyDir/data" ]; then
            cp -r ${defaultPolicySrc} $policyDir/data
            if [ -d "${opaPolicyDir}" ]; then
              chown -R ${opaUser}:${opaUser} ${opaPolicyDir}
            fi
          fi
          rm -rf $policyDir/.cache/*
          if [ "$policyDir/data/vm-policies" ]; then
            for vm_path in $policyDir/data/vm-policies/*; do
              if [ -d "$vm_path" ]; then
                # Get the folder name (e.g., "vm-a")
                vm_name=$(basename "$vm_path")
                echo "Packaging $vm_name..."
                ${pkgs.gnutar}/bin/tar --sort=name \
                  --mtime='@0' \
                  --owner=0 --group=0 --numeric-owner \
                  -czf "$policyDir/.cache/$vm_name.tar.gz" \
                  -C $policyDir/data/vm-policies "$vm_name"
              fi
            done
            echo "${cfg.policy.rev}" > $policyDir/.cache/.rev
          fi
        '';
      in
      {
        description = "GIVC admin module.";
        enable = true;
        after = [ "network.target" ];
        wants = [ "network.target" ];
        wantedBy = [ "multi-user.target" ];
        serviceConfig = {
          Type = "exec";
          ExecStart = "${givc-admin}/bin/givc-admin ${args}";
          Restart = "on-failure";
          TimeoutStopSec = 5;
          RestartSec = 1;
          ExecStartPre = "!${preStartScript}";
        };
        path = [
          pkgs.gzip
        ];
        environment = {
          "NAME" = "${cfg.name}";
          "TYPE" = "4";
          "SUBTYPE" = "5";
          "TLS" = "${trivial.boolToString cfg.tls.enable}";
          "SERVICES" = "${concatStringsSep " " cfg.services}";
          "POLICY_UPDATER" = "${trivial.boolToString updatercfg.enable}";
          "POLICY_URL" = "${cfg.policy.url}";
          "POLICY_UPDATE_INTERVAL" = "${builtins.toString updatercfg.interval}";
          "POLICY_UPDATE_REF" = "${updatercfg.ref}";
        }
        // attrsets.optionalAttrs cfg.tls.enable {
          "CA_CERT" = "${cfg.tls.caCertPath}";
          "HOST_CERT" = "${cfg.tls.certPath}";
          "HOST_KEY" = "${cfg.tls.keyPath}";
        }
        // attrsets.optionalAttrs cfg.debug {
          "RUST_BACKTRACE" = "1";
          "GIVC_LOG" = "givc=debug,info";
        };
      };

    networking.firewall.allowedTCPPorts = unique (
      (map (addr: strings.toInt addr.port) tcpAddresses) ++ lib.optional opacfg.enable opaServerPort
    );
  };
}
