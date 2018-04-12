BINDIRS=router
clean_BINDIRS=$(addprefix clean_,$(BINDIRS))

.PHONY: $(BINDIRS)

all: $(BINDIRS)

$(BINDIRS): bin
	$(MAKE) -C $@

bin:
	mkdir bin

clean: $(clean_BINDIRS)

$(clean_BINDIRS):
	$(MAKE) -C $(patsubst clean_%,%,$@) clean
