#!/usr/bin/env python3
import random

from ..utils.helpers import in_exception

def equality_to_approximation_obfuscation(parsed_structure, transform_func=None):
	"""
	Convert equality matches to approximation matches following Go EqualityToApproxMatchFilterObf pattern.

	Accepts transform_func for API consistency with other strategies, but walks
	the AST directly since it needs to modify the operator token (which the
	standard leaf visitor doesn't support).
	"""
	def obfuscate_operator(attr, operator, value):
		if in_exception(attr):
			return attr, value, operator
		if operator == "=" and random.choice([True, False]):
			return attr, value, "~="
		return attr, value, operator

	if transform_func is not None:
		# Use the visitor, but we need operator mutation — walk via custom logic
		pass

	def transform_operators(structure):
		if not structure:
			return

		for i in range(len(structure)):
			if isinstance(structure[i], list):
				transform_operators(structure[i])
			elif (isinstance(structure[i], dict) and
				  structure[i].get("type") == "Attribute" and
				  i + 2 < len(structure) and
				  isinstance(structure[i+1], dict) and
				  structure[i+1].get("type") == "ComparisonOperator" and
				  isinstance(structure[i+2], dict) and
				  structure[i+2].get("type") == "Value"):

				attr = structure[i].get("content", "")
				operator = structure[i+1].get("content", "")
				value = structure[i+2].get("content", "")

				new_attr, new_value, new_operator = obfuscate_operator(attr, operator, value)

				if new_attr != attr:
					structure[i]["content"] = new_attr
				if new_operator != operator:
					structure[i+1]["content"] = new_operator
				if new_value != value:
					structure[i+2]["content"] = new_value

	transform_operators(parsed_structure)
