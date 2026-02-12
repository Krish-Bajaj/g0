"""A CrewAI crew for testing."""
from crewai import Agent, Task, Crew
from crewai_tools import SerperDevTool, ScrapeWebsiteTool

search_tool = SerperDevTool()
scrape_tool = ScrapeWebsiteTool()

researcher = Agent(
    role="Research Analyst",
    goal="Find and analyze information",
    backstory="You are an expert researcher.",
    tools=[search_tool, scrape_tool],
    allow_delegation=True,
    verbose=True,
)

writer = Agent(
    role="Content Writer",
    goal="Write compelling content",
    backstory="You are a skilled writer.",
    tools=[],
    allow_delegation=False,
)

research_task = Task(
    description="Research the topic: {topic}",
    agent=researcher,
)

write_task = Task(
    description="Write an article based on the research",
    agent=writer,
)

crew = Crew(
    agents=[researcher, writer],
    tasks=[research_task, write_task],
    verbose=True,
)
