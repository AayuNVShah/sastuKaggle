from rdflib import Graph

# Load your RDF data
g = Graph()
g.parse("dataset.owl", format="xml")  # Load your OWL file

# Define and execute a SPARQL query
query = """
PREFIX ex: <http://example.org/ontology#>
SELECT ?snippet ?language ?isMalicious
WHERE {
    ?snippet rdf:type ex:CodeSnippet .
    ?snippet ex:isMalicious ?isMalicious .
}
"""

results = g.query(query)

# Process results
for row in results:
    if int(row.isMalicious) == 1:
        print(f"Snippet URI: {row.snippet}, Language: {row.language}, Malicious Status: {row.isMalicious}")
