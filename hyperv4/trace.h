#define WPP_CHECK_FOR_NULL_STRING  //to prevent exceptions due to NULL strings

#define WPP_CONTROL_GUIDS                                            \
	WPP_DEFINE_CONTROL_GUID(Hyperv4TraceGuid,                        \
	(7BE4956F,7478,4ABE,A08E,20E47B2D4664), \
	WPP_DEFINE_BIT(ERROR_LEVEL)     \
	WPP_DEFINE_BIT(DBG_LEVEL)       \
	)                                    

#define WPP_LEVEL_FLAGS_LOGGER(lvl,flags) WPP_LEVEL_LOGGER(flags)
#define WPP_LEVEL_FLAGS_ENABLED(lvl, flags) (WPP_LEVEL_ENABLED(flags) && WPP_CONTROL(WPP_BIT_ ## flags).Level  >= lvl)
