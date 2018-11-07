SRN=srn-dev
BINDIRS=router endhost server
clean_BINDIRS=$(addprefix clean_,$(BINDIRS))

.PHONY: $(BINDIRS) $(SRN)

all: $(BINDIRS)

$(BINDIRS): bin $(SRN)
	$(MAKE) -C $@

$(SRN):
	$(MAKE) -C $@

bin:
	mkdir bin

clean: $(clean_BINDIRS) srn-dev-clean

srn-dev-clean:
	$(MAKE) -C srn-dev clean

$(clean_BINDIRS):
	$(MAKE) -C $(patsubst clean_%,%,$@) clean
