{% extends "mail_templated/base.tpl" %}

{% block subject %}
Password Reset
{% endblock %}

{% block html %}
{{reset_link}}
{% endblock %}