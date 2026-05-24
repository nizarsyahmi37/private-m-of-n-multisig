# LP-0002 Private M-of-N Multisig — SPEL Program
#
# Quick start:
#   make build idl deploy setup
#   make cli ARGS="<command> --arg1 value1"
#
# Prerequisites:
#   - Rust + rzup (for guest builds; see CI workflow)
#   - LSSA wallet CLI (`wallet` binary, from logos-execution-zone)
#   - logos-blockchain-circuits v0.4.2 at ~/.logos-blockchain-circuits/
#     or pointed at by LOGOS_BLOCKCHAIN_CIRCUITS env var (required to
#     build the CLI; not needed for idl-gen or workspace tests)

SHELL := /bin/bash
STATE_FILE := .private-multisig-state
IDL_FILE := private_multisig.idl.json
PROGRAMS_DIR := methods/guest/target/riscv32im-risc0-zkvm-elf/docker
PROGRAM_BIN := $(PROGRAMS_DIR)/private_multisig.bin

# Load saved state if it exists
-include $(STATE_FILE)

define save_var
	@grep -v '^$(1)=' $(STATE_FILE) 2>/dev/null > $(STATE_FILE).tmp || true
	@echo '$(1)=$(2)' >> $(STATE_FILE).tmp
	@mv $(STATE_FILE).tmp $(STATE_FILE)
endef

.PHONY: help build idl cli deploy setup inspect status clean test deny

help: ## Show this help
	@echo "LP-0002 Private M-of-N Multisig"
	@echo ""
	@echo "  make build       Build the guest binary (needs rzup)"
	@echo "  make idl         Generate IDL from program source"
	@echo "  make cli ARGS=   Run the IDL-driven CLI (reads spel.toml)"
	@echo "  make deploy      Deploy program to sequencer"
	@echo "  make setup       Create signer account via wallet"
	@echo "  make inspect     Show ProgramId for built binary"
	@echo "  make status      Show saved state and binary info"
	@echo "  make test        Run all workspace tests"
	@echo "  make deny        Run cargo deny check"
	@echo "  make clean       Remove saved state"
	@echo ""
	@echo "Example:"
	@echo "  make build idl deploy"
	@echo "  make cli ARGS=\"--help\""
	@echo "  make cli ARGS=\"create-multisig --create-key 00..00 --members-root 00..00 -m 2 -n 3\""

build: ## Build the guest binary
	cargo risczero build --manifest-path methods/guest/Cargo.toml
	@echo ""
	@echo "✅ Guest binary built: $(PROGRAM_BIN)"
	@ls -la $(PROGRAM_BIN) 2>/dev/null || true

idl: ## Generate IDL JSON from program source
	cargo run -p private_multisig_idl_gen > $(IDL_FILE)
	@echo "✅ IDL written to $(IDL_FILE)"

cli: ## Run the IDL-driven CLI (ARGS="...")
	cargo run --manifest-path cli/Cargo.toml -- $(ARGS)

deploy: ## Deploy program to sequencer
	@test -f "$(PROGRAM_BIN)" || (echo "ERROR: Binary not found. Run 'make build' first."; exit 1)
	wallet deploy-program $(PROGRAM_BIN)
	@echo "✅ Program deployed"

inspect: ## Show ProgramId for built binary
	cargo run --manifest-path cli/Cargo.toml -- inspect $(PROGRAM_BIN)

setup: ## Create accounts needed for the program
	@echo "Creating signer account..."
	$(eval SIGNER_ID := $(shell wallet account new public 2>&1 | sed -n 's/.*Public\/\([A-Za-z0-9]*\).*/\1/p'))
	@echo "Signer: $(SIGNER_ID)"
	$(call save_var,SIGNER_ID,$(SIGNER_ID))
	@echo ""
	@echo "✅ Account saved to $(STATE_FILE)"

status: ## Show saved state and binary info
	@echo "LP-0002 Status"
	@echo "──────────────────────────────────────"
	@if [ -f "$(STATE_FILE)" ]; then cat $(STATE_FILE); else echo "(no state — run 'make setup')"; fi
	@echo ""
	@echo "Binaries:"
	@ls -la $(PROGRAM_BIN) 2>/dev/null || echo "  private_multisig.bin: NOT BUILT (run 'make build')"
	@echo ""
	@echo "IDL:"
	@ls -la $(IDL_FILE) 2>/dev/null || echo "  $(IDL_FILE): NOT GENERATED (run 'make idl')"

test: ## Run the full workspace test suite
	cargo test --workspace

deny: ## Run cargo deny check (advisories, bans, licenses, sources)
	cargo deny check

clean: ## Remove saved state and the generated IDL
	rm -f $(STATE_FILE) $(STATE_FILE).tmp $(IDL_FILE)
	@echo "✅ State cleaned"
