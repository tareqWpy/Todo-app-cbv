{% extends "mail_templated/base.tpl" %}

{% block subject %}
Account Activation
{% endblock %}

{% block html %}
{{activation_link}}
{% endblock %}