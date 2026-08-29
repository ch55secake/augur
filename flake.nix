{
  description = "Watch over active SSH connections and terminate unrecognized ones";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs =
    { nixpkgs, ... }:
    let
      systems = [
        "aarch64-darwin"
        "aarch64-linux"
        "x86_64-linux"
      ];

      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        {
          default = pkgs.buildGoModule {
            pname = "augur";
            version = "0.1.0";
            src = ./.;
            go = pkgs.go_1_26;
            vendorHash = null;
            subPackages = [ "cmd/augur" ];
            postInstall = ''
              install -Dm644 ${./packaging/com.ch55secake.augur.plist} \
                "$out/share/launchd/com.ch55secake.augur.plist"
              install -Dm644 ${./config/augur.example.json} \
                "$out/share/augur/config.example.json"
              substituteInPlace "$out/share/launchd/com.ch55secake.augur.plist" \
                --replace-fail /usr/local/bin/augur "$out/bin/augur"
            '';
          };
        }
      );

      devShells = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        {
          default = pkgs.mkShell {
            packages = [ pkgs.go_1_26 ];
          };
        }
      );

      formatter = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        pkgs.nixfmt
      );
    };
}
