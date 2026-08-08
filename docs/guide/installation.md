# Installation

```
pip install vyrion
```

That covers the core tool and `vyrion demo`. To run the live gates for a specific
framework, add its extra:

```
pip install "vyrion[langgraph]"
pip install "vyrion[crewai]"
```

Each framework has its own extra so their dependency pins never collide in one
environment. The two Node frameworks install with npm:

```
npm install genkit ai
```

Requires Python 3.9 or newer. The Node guard needs Node 18 or newer.
