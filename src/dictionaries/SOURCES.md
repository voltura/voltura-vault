# Generator dictionaries

- `eff.txt` is the Electronic Frontier Foundation [long wordlist](https://www.eff.org/dice) under [CC BY 3.0 US](https://www.eff.org/copyright). SHA-256 `addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e`.
- `sv-diceware-7776.plain.txt` is the [Swedish Diceware list](https://github.com/wytrych/swedish-diceware/tree/08dbdf8333f32f819c8c7eb8bb0abddcd4df60d8) by Marcin Wolniewicz. See the accompanying attribution and license. SHA-256 `cf2706ff96737762783ba95d71d4d6220d4c5a3c56f5894e962e29bdb19ee7fc`.

The generator adds Swedish words containing å, ä and ö to the transliterated Swedish list, then normalizes and deduplicates the combined pool.
