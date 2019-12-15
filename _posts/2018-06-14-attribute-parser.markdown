---
title: "HackerRank - Attribute Parser"
date: 2018-06-14 11:39:00
tags: [hackerrank, parsers]
categories: [hackerrank]
---

<!--more-->
### Attribute Parser

You are given the source code in HRML format consisting of lines. You have to answer queries. Each query asks you to print the value of the attribute specified. Print "Not Found!" if there isn't any such attribute.

[Attribute Parser](https://www.hackerrank.com/challenges/attribute-parser/problem "Complete Description"){: target="blank" }

Yeah parsers ! But we need to write a grammar first. Let's do it

```

<attribute>         ::=     <name> = " <attr_val> "
                            {
                                current_tag.add_attr(name.lexeme, attr_val.lexeme)
                            }

<attribute_list>    ::=     ε
                    |       <attribute> <spaces> <attribute_list>

<tag_decl>          ::=     ε
                    |
                            "<" <name>
                            {
                                new_tag = new Tag()
                                new_tag.name = name.lexeme
                                new_tag.parent = current_tag
                                current_tag = new_tag
                            }
                            <spaces> <attribute_list> <spaces> ">"
                            <tag_decl>
                            "</" <name> ">"
                            {
                                if (name.lexeme != current_tag.name.lexeme)
                                    error();
                                current_tag = current_tag.parent
                            }

<source>            ::=     ε
                    |       {
                                root_tag = new Tag()
                                root_tag.name = "/"
                                root_tag.parent = null
                                current_tag = root_tag
                            }
                            <tag_decl> <spaces> <source>

<attr_val>          ::=     [^\"]*
<name>              ::=     [A-Za-z_][A-Z0-9_a-z]*
<spaces>            ::=     [:space:]+
```

**'source'** is the start symbol here.  
We can see that the grammar is **LL(2)** because minimum two symbols are required to distinguish the start of **'tag\_decl'** from the closing of **'tag\_decl'**

[Implementation in C](https://github.com/x0r19x91/parsers/blob/5c96a6f5b9954ea4eff68b8b307fdfd4b84bd3f2/attr_parser.c){: target="blank"}  
[Implementation in Java](https://github.com/x0r19x91/parsers/blob/5c96a6f5b9954ea4eff68b8b307fdfd4b84bd3f2/AttributeParser.java){: target="blank"}
