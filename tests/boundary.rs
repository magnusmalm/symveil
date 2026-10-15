use symveil::build_engine;
use symveil::category::Category;
use symveil::config::RedactSection;
use symveil::vault::Vault;

#[test]
fn code_names_follow_the_feature_flag() {
    let mut vault = Vault::ephemeral();
    vault
        .assign("acme_falcon_init", Category::Function, None)
        .unwrap();
    let redact = RedactSection {
        internal_domains: Vec::new(),
        ..RedactSection::default()
    };
    let mut engine = build_engine(vault, &redact).unwrap();
    let input = "call acme_falcon_init()";
    let (out, hits) = engine.redact_str(input).unwrap();
    let masked = !out.contains("acme_falcon_init");
    #[cfg(feature = "identifiers")]
    {
        assert!(masked, "{out}");
        assert_eq!(hits.len(), 1);
        assert_eq!(engine.restore_str(&out), input);
    }
    #[cfg(not(feature = "identifiers"))]
    {
        assert!(!masked, "{out}");
        assert!(hits.is_empty());
        assert_eq!(out, input);
    }
}
