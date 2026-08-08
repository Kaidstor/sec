{
  description = "sec — локальный менеджер секретов, безопасный для работы с агентами";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
      version = if self ? shortRev then self.shortRev else "dev";
    in
    {
      packages = forAll (pkgs: rec {
        sec = pkgs.buildGoModule {
          pname = "sec";
          inherit version;
          src = ./cli;
          vendorHash = null; # vendor/ закоммичен — сеть при сборке не нужна

          # те же переменные, что у goreleaser (.goreleaser.yaml)
          ldflags = [
            "-s"
            "-w"
            "-X github.com/kaidstor/sec/internal/command.version=${version}"
          ];
          env.CGO_ENABLED = 0;

          # go test зовёт git/keychain-утилиты не везде доступные в sandbox —
          # тестовый гейт остаётся за CI репозитория
          doCheck = false;

          postInstall = ''
            mkdir -p $out/share/zsh/site-functions $out/share/bash-completion/completions $out/share/fish/vendor_completions.d
            $out/bin/sec completion zsh  > $out/share/zsh/site-functions/_sec
            $out/bin/sec completion bash > $out/share/bash-completion/completions/sec
            $out/bin/sec completion fish > $out/share/fish/vendor_completions.d/sec.fish
          '';

          meta = with pkgs.lib; {
            description = "Local secrets manager built for agent-safe workflows (values never hit argv, shell history, or chat)";
            homepage = "https://github.com/kaidstor/sec";
            license = licenses.mit;
            mainProgram = "sec";
          };
        };
        default = sec;
      });
    };
}
