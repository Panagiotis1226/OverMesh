# Homebrew formula template for the OverMesh node (daemon + CLI).
#
# To publish: create a tap repo (e.g. panagiotis1226/homebrew-overmesh),
# copy this file in as Formula/overmesh.rb, and fill in the release URL
# + sha256 for each published version. Users then run:
#   brew install panagiotis1226/overmesh/overmesh
#   sudo brew services start overmesh   # runs overmeshd as root (TUN)
class Overmesh < Formula
  desc "Self-hosted WireGuard overlay mesh VPN (node daemon + CLI)"
  homepage "https://github.com/panagiotis1226/overmesh"
  # Replace VERSION and the sha256 values when cutting a release:
  url "https://github.com/panagiotis1226/overmesh/archive/refs/tags/VERSION.tar.gz"
  sha256 "FILL_ME_IN"
  license "MIT"

  depends_on "go" => :build

  def install
    ldflags = "-s -w -X github.com/panagiotis1226/overmesh/internal/version.Version=#{version}"
    system "go", "build", *std_go_args(ldflags:, output: bin/"overmeshd"), "./cmd/overmeshd"
    system "go", "build", *std_go_args(ldflags:, output: bin/"overmesh"), "./cmd/overmesh"
  end

  service do
    run [opt_bin/"overmeshd"]
    require_root true
    keep_alive true
    log_path var/"log/overmeshd.log"
    error_log_path var/"log/overmeshd.log"
  end

  test do
    assert_match "overmesh", shell_output("#{bin}/overmesh version")
  end
end
