PLATFORMS = windows/amd64 windows/arm64 darwin/amd64 darwin/arm64 linux/amd64 linux/arm64

common.mk:
	@curl -fsSL https://raw.githubusercontent.com/alex27riva/go-mk/main/common.mk -o $@

include common.mk
