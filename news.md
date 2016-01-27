---
layout: default
title: News
---
<div class="page-content wc-container">
	<h1>News</h1>
	{% for post in site.posts %}
		{% if post.categories contains 'news' %}
			{% capture currentyear %}{{post.date | date: "%Y"}}{% endcapture %}
			{% if currentyear != year %}
				<h3>{{ currentyear }}</h3>
				{% capture year %}{{currentyear}}{% endcapture %} 
			{% endif %}
			<h5>{{ post.title }}</h5>
			<p>
			{{ post.content }}
	       		{% for tag in post.tags %}
				#{{ tag }}
				{% unless forloop.last %}, {% endunless %}
               		{% endfor %}
			</p>
		{% endif %}
        {% endfor %}
</div>
