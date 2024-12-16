import pandas as pd
from rdflib import Graph, Namespace, RDF, Literal, URIRef
from rdflib.namespace import RDFS, OWL

# Load dataset (ensure 'data.csv' is in the correct path)
df = pd.read_csv('data.csv')

# Define namespaces
EX = Namespace("http://example.org/ontology#")

# Initialize graph
g = Graph()

# Bind namespaces
g.bind("ex", EX)
g.bind("rdfs", RDFS)
g.bind("owl", OWL)

# Define classes
CodeSnippet = URIRef(EX.CodeSnippet)
g.add((CodeSnippet, RDF.type, OWL.Class))
g.add((CodeSnippet, RDFS.label, Literal("Code Snippet")))

# Define properties
language_prop = URIRef(EX.language)
is_malicious_prop = URIRef(EX.isMalicious)
g.add((language_prop, RDF.type, OWL.DatatypeProperty))
g.add((language_prop, RDFS.label, Literal("Code Language")))
g.add((is_malicious_prop, RDF.type, OWL.DatatypeProperty))
g.add((is_malicious_prop, RDFS.label, Literal("Is Malicious")))

# Add individuals from the dataset
for idx, row in df.iterrows():
    snippet_uri = URIRef(EX[f"CodeSnippet_{idx}"])
    g.add((snippet_uri, RDF.type, CodeSnippet))
    g.add((snippet_uri, language_prop, Literal(row['Language'])))
    g.add((snippet_uri, RDFS.comment, Literal(row['CodeSnippet'])))
    g.add((snippet_uri, is_malicious_prop, Literal(row['Label'])))

# Save ontology to a file
output_file = "dataset.owl"
g.serialize(destination=output_file, format="xml")
print(f"OWL ontology saved to {output_file}")
