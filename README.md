# Fingerprinting Composite Homograph Attacks Using Shannon Entropy and Log Loss Transformation

The speed of homograph phishing and impersonation campaigns have increased since threat actors can now generate and deploy thousand of Just-in-Time, lookalike domains within seconds. This has outpaced conventional threat intelligence feeds and lexical machine-learning models. The existing system fails to catch freshly registered domains due to its reliance often on surface-level markers, aesthetic modifications, or known blacklists. 

This work presents a structural based approach in detecting composite homograph attack through occurrence analysis of character transformations. Given a URL, the solution applies Shannon Entropy and Log Loss Transformation, measuring the average surprise associated with fingerprints often left by AI-generated phishing such as mixed alphabet scripts, non-ASCII lookalike individual substitutions, and structural spikes associated from domain-generation algorithms. By doing so, we’ve achieved a lightweight solution in milliseconds with 96% detection accuracy in identifying suspicious composite homograph URLs. 

## Citations
```
@article{nguyen2026shannon,
  title   = {Fingerprinting Composite Homograph Attacks Using Shannon Entropy and Log Loss Transformation},
  author  = {H. Nguyen, T. Nguyen, A. Rumbos},
  journal = {Women in Cybersecurity Abstract},
  year    = {2026}
}
```
## Acknowledgements
Homograph and real domains are sourced from [Glyphnet](https://github.com/Akshat4112/Glyphnet/tree/master)

## License
Released under the [Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0)
