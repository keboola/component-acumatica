Configure the Acumatica connection and the list of tables to write.

Each table entry maps an input CSV file to an Acumatica entity endpoint. Records are upserted via PUT — Acumatica identifies existing records by their natural key fields included in the CSV.
