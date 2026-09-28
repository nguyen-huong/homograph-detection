# Mechanism-Aware Homograph Detection Using Shannon Entropy

In the age of frontier AI, the speed of homograph phishing and impersonation campaigns have increased since threat actors can now generate and deploy thousand of Just-in-Time, lookalike domains within seconds. This has outpaced conventional threat intelligence feeds and lexical machine-learning models. The existing system fails to catch freshly registered domains due to its reliance often on surface-level markers, aesthetic modifications, or known blacklists. 

This work presents a structural based approach in detecting composite homograph attack. Given a URL, the solution applies Shannon Entropy and Log Loss Transformation, measuring the average surprise associated with fingerprints often left by AI-generated phishing such as mixed alphabet scripts, non-ASCII lookalike individual substitutions, and structural spikes associated from domain-generation algorithms. By doing so, we’ve achieved a lightweight solution in milliseconds with 96% detection accuracy in identifying suspicious composite homograph URLs. 

## Citations
```
@article{nguyen2026shannon,
  title   = {Mechanism-Aware Homograph Detection Using Shannon Entropy},
  author  = {Nguyen, Huong, Vy Nguyen, Adolfo J. Rumbos},
  journal = {Women in Cybersecurity 2026-2027},
  year    = {2026}
}
```
