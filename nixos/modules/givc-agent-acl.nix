# SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
# SPDX-License-Identifier: Apache-2.0

{
  config,
  lib,
  ...
}:

with lib;
let
  cfg = config.givc.accessControl;
in
{
  config = mkIf cfg.enable {
    givc.accessControl.extraRules = {
      permit = [
        {
          sources = [ cfg.adminVm ];
          modules = [ "locale.LocaleClient" ];
        }
        {
          sources = [ cfg.adminVm ];
          modules = [ "systemd.UnitControlService" ];
          actions = [ "GetUnitStatus" ];
        }
      ];
    };
  };
}
