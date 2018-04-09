BINDIRS=router
clean_BINDIRS=$(addprefix clean_,$(BINDIRS))

.PHONY: $(BINDIRS)

all: $(BINDIRS)

$(BINDIRS):
	$(MAKE) -C $@

clean: $(clean_BINDIRS)

$(clean_BINDIRS):
	$(MAKE) -C $(patsubst clean_%,%,$@) clean
