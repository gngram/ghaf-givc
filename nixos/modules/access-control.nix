# SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
# SPDX-License-Identifier: Apache-2.0

{
  config,
  lib,
  pkgs,
  ...
}:

with lib;

let
  cfg = config.givc.accessControl;

  inherit (import ./definitions.nix { inherit config lib; })
    applicationSubmodule
    ;

  generatedRulesText =
    if cfg.cedarRulesFile != null then
      builtins.readFile cfg.cedarRulesFile
    else
      (concatMapStringsSep "\n" (generateRule "permit") cfg.extraRules.permit)
      + "\n"
      + (concatMapStringsSep "\n" (generateRule "forbid") cfg.extraRules.forbid);

  policyFile = pkgs.writeText "policies.cedar" generatedRulesText;

  validatedCedarRules =
    pkgs.runCommand "validated-cedar-policies.cedar"
      {
        nativeBuildInputs = [ pkgs.cedar ];
      }
      ''
        echo "Verifying Cedar rules ..."

        cedar validate \
          --schema ${./schema.ced} \
          --policies ${policyFile}

        cp ${policyFile} $out
      '';

  # Generate Arg condition
  mapCondition =
    cond: argName: target:
    let
      toCedarValue =
        v:
        if isString v then
          ''"${v}"''
        else if isBool v then
          (if v then "true" else "false")
        else
          toString v;
      targetList = "[ " + (concatStringsSep ", " (map toCedarValue target)) + " ]";
      firstTarget = toCedarValue (head target);
    in
    {
      # Equality checks
      "is" = "context.${argName} == ${firstTarget}";
      "not-is" = "context.${argName} != ${firstTarget}";

      # 'contains' checks if the context value contains the target head
      "contains" = "context.${argName}.contains(${firstTarget})";

      # 'in' checks if the context value exists within the provided Nix list
      "in" = "${targetList}.contains(context.${argName})";

      # 'not-in' negates the 'in' logic
      "not-in" = "!${targetList}.contains(context.${argName})";

      # Pattern matching
      "like" = "context.${argName} like ${firstTarget}";
    }
    .${cond};

  # Context Logic
  genContext =
    ctx:
    let
      baseLogic = mapCondition ctx.condition ctx.argName ctx.targets;
    in
    if ctx.joinOp != null then
      if ctx.optional then
        "${ctx.joinOp}\n      (context has ${ctx.argName} && ${baseLogic})"
      else
        "${ctx.joinOp}\n      ${baseLogic}"
    else if ctx.optional then
      "(context has ${ctx.argName} && ${baseLogic})"
    else
      baseLogic;

  # Main Rule
  generateRule =
    effect: rule:
    let
      toCedarList =
        prefix: list: "[ " + (concatStringsSep ", " (map (x: ''${prefix}::"${x}"'') list)) + " ]";

      pWhen =
        if length rule.sources == 1 then
          [ "principal == Source::\"${head rule.sources}\"" ]
        else if length rule.sources > 1 then
          [ "principal in ${toCedarList "Source" rule.sources}" ]
        else
          [ ];
      aWhen =
        if length rule.actions == 1 then
          [ "action == Command::\"${head rule.actions}\"" ]
        else if length rule.actions > 1 then
          [ "action in ${toCedarList "Command" rule.actions}" ]
        else
          [ ];
      rWhen =
        if length rule.modules == 1 then
          [ "resource == Module::\"${head rule.modules}\"" ]
        else if length rule.modules > 1 then
          [ "resource in ${toCedarList "Module" rule.modules}" ]
        else
          [ ];

      contextWhen = map genContext rule.context;
      allContext = if length contextWhen > 0 then "( ${concatStringsSep " " contextWhen} \n    )" else "";

      allConditions = pWhen ++ aWhen ++ rWhen ++ (if allContext != "" then [ allContext ] else [ ]);
    in
    ''
      ${effect} (
          principal,
          action,
          resource
      )${
        optionalString (
          allConditions != [ ]
        ) "\nwhen {\n    ${concatStringsSep " && \n    " allConditions}\n}"
      };
    '';

  accessControlOptions = types.submodule {
    options = {
      sources = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "List of VM IPs.";
      };
      actions = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "Givc RPC methods.";
      };
      modules = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "Givc module full name which includes the RPC method.";
      };
      context = mkOption {
        description = "Arguments check in the RPC context.";
        default = [ ];
        type = types.listOf (
          types.submodule {
            options = {
              argName = mkOption {
                type = types.nullOr types.str;
                default = null;
                description = "Argument name in the context.";
              };
              optional = mkOption {
                type = types.bool;
                default = false;
                description = "Do not fail if argument is missing.";
              };
              condition = mkOption {
                type = types.nullOr (
                  types.enum [
                    "is"
                    "not-is"
                    "in"
                    "not-in"
                    "contains"
                    "like"
                  ]
                );
                default = null;
                description = "Logic:
                      'is' (==), equality check with targets[0]
                      'not-is' (!=),  inequality check with targets[0]
                      'in' (targets.contains(context.arg)),
                      'not-in' (!targets.contains),
                      'contains' (context.arg.contains(targets[0])), Other elements in targets are ignored.
                      'like' (pattern).";
              };
              targets = mkOption {
                type = types.nullOr (
                  types.listOf (
                    types.oneOf [
                      types.str
                      types.int
                      types.bool
                    ]
                  )
                );
                default = null;
                description = "List of values to compare against.";
              };
              joinOp = mkOption {
                type = types.nullOr (
                  types.enum [
                    "&&"
                    "||"
                  ]
                );
                default = null;
                description = "Logical operator to join context conditions.";
              };
            };
          }
        );
      };
    };
  };

in
{
  options.givc.accessControl = {
    enable = mkEnableOption "access control for givc-agent and givc-admin";
    cedarRulesFile = mkOption {
      type = types.nullOr types.path;
      description = ''
        Access control policy file (Cedar syntax). If provided, all default built-in rules are ignored.
        Entities: 
        principal = Source::"<vm-name>" (source VM, e.g. "admin-vm"), 
        action = Command::"<rpc-method>" (gRPC method, e.g. "StartApplication"), 
        resource = Module::"<grpc-module>" (gRPC service, e.g. "systemd.UnitControlService"), 
        context = runtime RPC call parameters (better to guard with `context has <field>` before use). 
      '';
      default = null;
    };

    adminVm = mkOption {
      type = types.str;
      default = "admin-vm";
      description = "Name of the admin VM, that manages the administeredServices and trustedApps.";
    };

    administeredServices = mkOption {
      type = types.listOf types.str;
      default = [ ];
    };

    trustedApps = mkOption {
      type = types.nullOr (types.listOf applicationSubmodule);
      default = [ ];
    };

    extraRules = {
      permit = mkOption {
        type = types.listOf accessControlOptions;
        default = [ ];
        description = "List of allow-rules.";
      };
      forbid = mkOption {
        type = types.listOf accessControlOptions;
        default = [ ];
        description = "List of deny-rules (precedence over permit).";
      };
    };
  };

  config = mkIf cfg.enable {

    givc.accessControl.extraRules.permit = mkMerge [
      (mkIf (length cfg.administeredServices > 0) [
        {
          sources = [ cfg.adminVm ];
          modules = [ "systemd.UnitControlService" ];
          context = [
            {
              argName = "UnitName";
              condition = "in";
              targets = cfg.administeredServices;
              optional = true;
            }
          ];
        }
      ])
      (mkIf (cfg.trustedApps != null && length cfg.trustedApps > 0) [
        {
          sources = [ cfg.adminVm ];
          modules = [ "systemd.UnitControlService" ];
          actions = [
            "StartApplication"
            "StopUnit"
          ];
          context = imap0 (i: app: {
            argName = "UnitName";
            condition = "like";
            targets = [ "${app.name}@*.service" ];
            optional = true;
            joinOp = if i > 0 then "||" else null;
          }) cfg.trustedApps;
        }
      ])
    ];

    environment.etc."givc-access-control.cedar".source =
      if cfg.cedarRulesFile == null then validatedCedarRules else cfg.cedarRulesFile;

  };
}
