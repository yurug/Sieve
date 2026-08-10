package gmail

import (
	"context"
	"fmt"

	"google.golang.org/api/calendar/v3"
)

// CalendarClient wraps the Google Calendar API.
type CalendarClient struct {
	service *calendar.Service
}

// NewCalendarClient creates a CalendarClient from an existing Calendar API service.
func NewCalendarClient(service *calendar.Service) *CalendarClient {
	return &CalendarClient{service: service}
}

// CalendarEvent represents a calendar event.
type CalendarEvent struct {
	ID          string   `json:"id"`
	Summary     string   `json:"summary"`
	Description string   `json:"description,omitempty"`
	Location    string   `json:"location,omitempty"`
	Start       string   `json:"start"`
	End         string   `json:"end"`
	Attendees   []string `json:"attendees,omitempty"`
	Status      string   `json:"status,omitempty"`
	HTMLLink    string   `json:"html_link,omitempty"`
}

// CalendarListResult contains the results of an event listing.
type CalendarListResult struct {
	Events        []CalendarEvent `json:"events"`
	NextPageToken string          `json:"next_page_token,omitempty"`
}

func eventTime(et *calendar.EventDateTime) string {
	if et == nil {
		return ""
	}
	if et.DateTime != "" {
		return et.DateTime
	}
	return et.Date
}

func parseEvent(e *calendar.Event) CalendarEvent {
	ev := CalendarEvent{
		ID:          e.Id,
		Summary:     e.Summary,
		Description: e.Description,
		Location:    e.Location,
		Start:       eventTime(e.Start),
		End:         eventTime(e.End),
		Status:      e.Status,
		HTMLLink:    e.HtmlLink,
	}
	for _, a := range e.Attendees {
		ev.Attendees = append(ev.Attendees, a.Email)
	}
	return ev
}

// ListEvents lists events from a calendar.
func (c *CalendarClient) ListEvents(ctx context.Context, calendarID string, timeMin, timeMax string, maxResults int64, pageToken string) (*CalendarListResult, error) {
	if calendarID == "" {
		calendarID = "primary"
	}
	if maxResults == 0 {
		maxResults = 100
	}
	if maxResults > 2500 {
		maxResults = 2500
	}

	call := c.service.Events.List(calendarID).Context(ctx).
		MaxResults(maxResults).
		SingleEvents(true).
		OrderBy("startTime")

	if timeMin != "" {
		call = call.TimeMin(timeMin)
	}
	if timeMax != "" {
		call = call.TimeMax(timeMax)
	}
	if pageToken != "" {
		call = call.PageToken(pageToken)
	}

	resp, err := call.Do()
	if err != nil {
		return nil, fmt.Errorf("calendar: listing events: %w", err)
	}

	result := &CalendarListResult{
		NextPageToken: resp.NextPageToken,
	}
	for _, e := range resp.Items {
		result.Events = append(result.Events, parseEvent(e))
	}
	return result, nil
}

// GetEvent returns a single calendar event.
func (c *CalendarClient) GetEvent(ctx context.Context, calendarID, eventID string) (*CalendarEvent, error) {
	if calendarID == "" {
		calendarID = "primary"
	}

	e, err := c.service.Events.Get(calendarID, eventID).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("calendar: getting event %s: %w", eventID, err)
	}

	ev := parseEvent(e)
	return &ev, nil
}

// CreateEvent creates a new calendar event.
func (c *CalendarClient) CreateEvent(ctx context.Context, calendarID string, summary, location, description, startTime, endTime string, attendees []string) (*CalendarEvent, error) {
	if calendarID == "" {
		calendarID = "primary"
	}

	event := &calendar.Event{
		Summary:     summary,
		Location:    location,
		Description: description,
	}

	if startTime != "" {
		event.Start = &calendar.EventDateTime{DateTime: startTime}
	}
	if endTime != "" {
		event.End = &calendar.EventDateTime{DateTime: endTime}
	}

	for _, email := range attendees {
		event.Attendees = append(event.Attendees, &calendar.EventAttendee{Email: email})
	}

	created, err := c.service.Events.Insert(calendarID, event).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("calendar: creating event: %w", err)
	}

	ev := parseEvent(created)
	return &ev, nil
}

// UpdateEvent updates an existing calendar event using PATCH semantics.
// EventPatch carries presence-aware fields for UpdateEvent. A nil pointer means
// "leave this field unchanged"; a non-nil pointer — INCLUDING an empty string —
// means "set it to this value". That distinction is what lets a caller clear a
// field: passing an explicit "" for location/description blanks it (via
// ForceSendFields) instead of being silently ignored, which the old
// `if x != ""` guards did.
type EventPatch struct {
	Summary     *string
	Location    *string
	Description *string
	StartTime   *string
	EndTime     *string
	// Attendees nil = leave unchanged; non-nil = REPLACE the whole attendee list
	// (Google's PATCH semantics — the API has no add/remove). An empty non-nil
	// slice clears all attendees. Callers adding one attendee must include the
	// existing ones, or they will be dropped.
	Attendees *[]string
}

func (c *CalendarClient) UpdateEvent(ctx context.Context, calendarID, eventID string, patch EventPatch) (*CalendarEvent, error) {
	if calendarID == "" {
		calendarID = "primary"
	}

	event := &calendar.Event{}
	// force names the API fields we send even when empty, so an explicit blank
	// clears them rather than being omitted (Google treats omitted as unchanged).
	var force []string
	if patch.Summary != nil {
		event.Summary = *patch.Summary
		if *patch.Summary == "" {
			force = append(force, "Summary")
		}
	}
	if patch.Location != nil {
		event.Location = *patch.Location
		if *patch.Location == "" {
			force = append(force, "Location")
		}
	}
	if patch.Description != nil {
		event.Description = *patch.Description
		if *patch.Description == "" {
			force = append(force, "Description")
		}
	}
	// Start/End can't be blanked (an event must have both), so an empty value is
	// treated as "leave unchanged".
	if patch.StartTime != nil && *patch.StartTime != "" {
		event.Start = &calendar.EventDateTime{DateTime: *patch.StartTime}
	}
	if patch.EndTime != nil && *patch.EndTime != "" {
		event.End = &calendar.EventDateTime{DateTime: *patch.EndTime}
	}
	if patch.Attendees != nil {
		event.Attendees = make([]*calendar.EventAttendee, 0, len(*patch.Attendees))
		for _, email := range *patch.Attendees {
			event.Attendees = append(event.Attendees, &calendar.EventAttendee{Email: email})
		}
		if len(*patch.Attendees) == 0 {
			force = append(force, "Attendees")
		}
	}
	event.ForceSendFields = force

	updated, err := c.service.Events.Patch(calendarID, eventID, event).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("calendar: updating event %s: %w", eventID, err)
	}

	ev := parseEvent(updated)
	return &ev, nil
}

// DeleteEvent deletes a calendar event.
func (c *CalendarClient) DeleteEvent(ctx context.Context, calendarID, eventID string) error {
	if calendarID == "" {
		calendarID = "primary"
	}

	err := c.service.Events.Delete(calendarID, eventID).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("calendar: deleting event %s: %w", eventID, err)
	}
	return nil
}
