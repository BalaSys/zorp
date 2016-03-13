---
layout: default
title: Blog archive
---
<div class="page-content wc-container">
	<h1>Blog Archive</h1>
	<ul>
	{% for post in site.posts %}
		{% if post.categories contains 'blog' %}
			{% capture currentyear %}{{post.date | date: "%Y"}}{% endcapture %}
			{% if currentyear != year %}
				</ul>
				<h5>{{ currentyear }}</h5>
				<ul class="posts">
				{% capture year %}{{currentyear}}{% endcapture %} 
			{% endif %}
			<li><a href="{{ post.url | prepend: site.baseurl }}">{{ post.title }}</a></li>
		{% endif %}
	{% endfor %}
	</ul>
</div>
